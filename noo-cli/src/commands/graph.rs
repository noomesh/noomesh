// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo graph …` — knowledge-graph exploration (Rust gateway
//! routes/knowledge.rs). All four Python commands ported: stats, search,
//! detail, neighbors — plus `recluster`, which is not a port: it restores an
//! entry point the Rust port dropped.
//!
//! Note: the Python graph commands send NO auth headers (401 against the
//! auth-enforcing gateway), and render field names from an older API shape
//! (`id`/`name`/`entity_type`); the gateway returns
//! `entity_id`/`canonical_name`/`type`. The Rust renderings accept both.

use super::{truncate, urlencode};
use crate::http::{get_json, post_json};
use crate::ui::{self, Col};
use crate::{Globals, Unhandled};

fn field<'a>(v: &'a serde_json::Value, keys: &[&str]) -> &'a str {
    keys.iter().find_map(|k| v[*k].as_str()).unwrap_or("?")
}

/// `noo graph stats` — GET /api/v1/graph/stats.
pub fn graph_stats(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/v1/graph/stats", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    println!("{}", ui::header("graph", None));
    // Same keys the Python rendering looks for; entity_types is a
    // {type: count} map rendered inline.
    let mut rows: Vec<(&str, String)> = Vec::new();
    // The gateway doesn't send total_entities — derive it from the type map
    // so the headline number is still present.
    if body.get("total_entities").is_none() {
        if let Some(map) = body["entity_types"].as_object() {
            let total: u64 = map.values().filter_map(|v| v.as_u64()).sum();
            rows.push(("total entities", total.to_string()));
        }
    }
    for (key, label) in [
        ("total_entities", "total entities"),
        ("total_edges", "total edges"),
        ("entity_types", "entity types"),
        ("documents_with_entities", "documents with entities"),
    ] {
        let Some(val) = body.get(key) else { continue };
        match val.as_object() {
            Some(map) => {
                let inline: Vec<String> = map.iter().map(|(k, v)| format!("{k} {v}")).collect();
                rows.push((label, inline.join(", ")));
            }
            None => rows.push((label, val.to_string())),
        }
    }
    print!("{}", ui::kv(&rows));
    Ok(0)
}

/// `noo graph search QUERY` — GET /api/v1/graph/entities?q=… (ILIKE match).
pub fn graph_search(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let query = match args {
        [q] if !q.starts_with('-') => q.clone(),
        _ => return Err(Unhandled),
    };
    let body = get_json(g, &format!("/api/v1/graph/entities?q={}", urlencode(&query)), true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let entities = body.as_array().or_else(|| body["entities"].as_array()).unwrap_or(&empty);
    if entities.is_empty() {
        println!("{}", ui::muted("no entities"));
        return Ok(0);
    }
    println!("{}", ui::header("entities", Some(&format!("{} matching {query}", entities.len()))));
    println!();
    let rows: Vec<Vec<String>> = entities
        .iter()
        .map(|e| {
            vec![
                ui::muted(field(e, &["entity_id", "id"])),
                truncate(field(e, &["canonical_name", "name"]), 40),
                field(e, &["type", "entity_type"]).to_string(),
            ]
        })
        .collect();
    print!("{}", ui::table(&[Col::left("id"), Col::left("name"), Col::left("type")], &rows));
    Ok(0)
}

/// `noo graph detail ENTITY_ID` — GET /api/v1/graph/entities/{id}.
pub fn graph_detail(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let entity_id = match args {
        [id] if !id.starts_with('-') => id.clone(),
        _ => return Err(Unhandled),
    };
    let body = get_json(g, &format!("/api/v1/graph/entities/{entity_id}"), true, 10);
    if g.json {
        println!("{body}");
    } else {
        // Parity with Python's console.print_json: nested detail object.
        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string()));
    }
    Ok(0)
}

/// `noo graph neighbors ENTITY_ID [--hops/-H N]` —
/// GET /api/v1/graph/entities/{id}/neighbors?hops=N (recursive edge walk;
/// gateway clamps hops to 1..=5).
pub fn graph_neighbors(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut entity_id: Option<String> = None;
    let mut hops = 1u64;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--hops" | "-H" => hops = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?,
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if entity_id.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(id) = entity_id else { return Err(Unhandled) };
    let body = get_json(
        g,
        &format!("/api/v1/graph/entities/{id}/neighbors?hops={hops}"),
        true,
        10,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let edges = body.as_array().or_else(|| body["neighbors"].as_array()).unwrap_or(&empty);
    if edges.is_empty() {
        println!("{}", ui::muted("no neighbors"));
        return Ok(0);
    }
    println!("{}", ui::header("neighbors", Some(&format!("{} edges · {hops} hops", edges.len()))));
    println!();
    let rows: Vec<Vec<String>> = edges
        .iter()
        .map(|e| {
            vec![
                e["depth"].as_u64().unwrap_or(1).to_string(),
                ui::muted(field(e, &["src_entity_id", "id"])),
                field(e, &["rel_type", "relation", "relationship"]).to_string(),
                ui::muted(field(e, &["dst_entity_id", "name"])),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(&[Col::right("depth"), Col::left("src"), Col::left("rel"), Col::left("dst")], &rows)
    );
    Ok(0)
}

/// `noo graph navigate <question> [-H <hops>] [-s <entity-id>]...` —
/// POST /api/v1/graph/navigate (seeds, expand, pages, paths).
///
/// The CLI's way to create a saved thread: a signed-in account's navigate is
/// kept as a walk (`noo walks`). Entity search never saves one. Intelligent
/// tier; Basic gets the add-on's own refusal.
pub fn graph_navigate(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let body = navigate_body(args).ok_or(Unhandled)?;
    // The gateway waits up to 120s for the worker; wait a little longer so a
    // late answer is heard rather than reported as a client timeout.
    let body = post_json(g, "/api/v1/graph/navigate", &body, true, 130);
    // The route holds the request a few seconds and, if the walk is slower,
    // answers 202 with an operation handle instead (gateway ops.rs): follow it.
    let body = match super::ops::settle(g, body, "navigation", 150) {
        Ok(b) => b,
        Err(code) => return Ok(code),
    };
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    if let Some(err) = body["error"].as_str() {
        ui::warned(err);
        return Ok(1);
    }
    let empty = Vec::new();
    let seeds = body["seed_entities"].as_array().unwrap_or(&empty);
    let hyps = body["hypotheses"].as_array().unwrap_or(&empty);
    let pages = body["candidate_page_ids"].as_array().map_or(0, |p| p.len());
    println!("{}", ui::header("navigate", Some(&format!("{} seeds · {} hypotheses · {pages} pages", seeds.len(), hyps.len()))));
    if seeds.is_empty() && hyps.is_empty() {
        println!("{}", ui::muted("the graph has nothing on that question"));
        return Ok(0);
    }
    for s in seeds.iter().take(5) {
        println!("  {} {}", field(s, &["canonical_name", "name"]), ui::muted(field(s, &["type", "entity_type"])));
    }
    if !hyps.is_empty() {
        println!();
        let rows: Vec<Vec<String>> = hyps
            .iter()
            .take(10)
            .map(|h| {
                vec![
                    h["confidence"].as_f64().map_or("?".to_string(), |c| format!("{c:.2}")),
                    truncate(field(h, &["description"]), 90),
                ]
            })
            .collect();
        print!("{}", ui::table(&[Col::right("conf"), Col::left("hypothesis")], &rows));
    }
    ui::guide(&[("noo walks", "this walk is saved as a thread while you are signed in and saving is on")]);
    Ok(0)
}

/// Parse `<question> [-H <hops>] [-s <entity-id>]...` into the request body.
/// `None` is a usage error. The question may be several unquoted words.
fn navigate_body(args: &[String]) -> Option<serde_json::Value> {
    let mut words: Vec<&str> = Vec::new();
    let mut hops: Option<u64> = None;
    let mut seeds: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--hops" | "-H" => hops = Some(iter.next()?.parse().ok()?),
            "--seed" | "-s" => seeds.push(iter.next()?.clone()),
            t if t.starts_with('-') => return None,
            t => words.push(t),
        }
    }
    let query = words.join(" ");
    if query.trim().is_empty() {
        return None;
    }
    let mut body = serde_json::json!({ "query": query });
    if let Some(h) = hops {
        body["max_hops"] = serde_json::json!(h);
    }
    if !seeds.is_empty() {
        body["seed_entities"] = serde_json::json!(seeds);
    }
    Some(body)
}

/// `noo graph recluster [--min-size N] [--resolution R]` —
/// POST /api/v1/graph/recluster.
///
/// Not a port: this is an entry point the Rust port dropped. It groups
/// related entities into labelled clusters, which
/// `/api/v1/graph/clusters/overview` then reports.
///
/// Intelligent tier: on Basic the gateway refuses with the add-on's own
/// message. The entity-level graph is built on every tier and needs no
/// clustering.
///
/// Slow by nature. The gateway runs it as an OPERATION and answers `202`
/// with a handle at once (no request is held that long). By default this
/// follows the operation with a spinner until it
/// finishes, so it still reads as one foreground command (`--wait`, the
/// default); `--no-wait` prints the operation id and returns, and
/// `noo ops show <id> --wait` picks it up. A second run started while one is
/// in flight is not queued: your own run is JOINED (same operation), and
/// another account's, or the worker's own, is reported as already running.
pub fn graph_recluster(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut min_size: Option<u32> = None;
    let mut resolution: Option<f64> = None;
    let mut wait = true;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--wait" => wait = true,
            "--no-wait" => wait = false,
            "--min-size" | "-m" => {
                min_size = Some(iter.next().ok_or(Unhandled)?.parse().map_err(|_| Unhandled)?)
            }
            "--resolution" | "-r" => {
                resolution = Some(iter.next().ok_or(Unhandled)?.parse().map_err(|_| Unhandled)?)
            }
            _ => return Err(Unhandled),
        }
    }
    let mut body = serde_json::Map::new();
    if let Some(m) = min_size {
        body.insert("min_cluster_size".into(), serde_json::json!(m));
    }
    if let Some(r) = resolution {
        body.insert("resolution".into(), serde_json::json!(r));
    }
    if !g.json {
        ui::step("clustering the knowledge graph — minutes, not seconds");
    }
    // The route answers at once (202 + handle): starting costs one short request.
    let body = post_json(g, "/api/v1/graph/recluster", &serde_json::Value::Object(body), true, 30);
    // `--no-wait` with no handle (the worker's own answer: already running, or a
    // refusal) falls through and is rendered like any other result.
    if !wait && super::ops::is_handle(&body) {
        super::ops::print_started(g, &body, "clustering");
        return Ok(0);
    }
    // The run is allowed 900s server-side; wait a little longer than that, so
    // a run that finishes at 899s is heard rather than reported as a timeout
    // the gateway never had.
    let body = match super::ops::settle(g, body, "clustering", 960) {
        Ok(b) => b,
        Err(code) => return Ok(code),
    };
    if let Err(code) = refuse_error_body(g, &body, "clustering") {
        return Ok(code);
    }
    if g.json {
        println!("{body}");
    } else if body["status"].as_str() == Some("already_running") {
        // Not a failure and not a success: nothing was started, and the run
        // the operator is asking about is still going.
        ui::warned(&format!(
            "a clustering run is already in flight ({}s elapsed) — this started nothing",
            body["elapsed_secs"].as_f64().unwrap_or(0.0)
        ));
        return Ok(0);
    } else {
        ui::done("clustered");
        let mut rows: Vec<Vec<String>> = Vec::new();
        for (key, label) in [
            ("clusters", "clusters"),
            ("meta_clusters", "meta clusters"),
            ("nodes", "entities"),
            ("edges", "edges"),
            ("stale_removed", "stale removed"),
            ("elapsed_secs", "seconds"),
        ] {
            if let Some(v) = body.get(key) {
                if !v.is_null() {
                    rows.push(vec![label.to_string(), v.to_string()]);
                }
            }
        }
        println!();
        print!("{}", ui::table(&[Col::left(""), Col::right("")], &rows));
        ui::guide(&[(
            "noo graph stats",
            "entity and edge totals — the level below the clusters",
        )]);
    }
    Ok(0)
}

/// How many of the largest clusters the human rendering lists. `--json` carries
/// every cluster the gateway returned.
const AUDIT_TOP: usize = 20;

/// `noo graph clusters audit` — GET /api/v1/graph/clusters/audit.
///
/// Read-only. How each knowledge-graph cluster mixes audience tiers, and what
/// a `{company, system}` reader (a non-admin with no teams) would see of it.
/// The measuring step before deciding whether clustering per audience tier is
/// worth building. Administrators only: the gateway answers anyone else 403
/// and nothing more, because the counts are the finding.
pub fn graph_clusters_audit(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/v1/graph/clusters/audit", true, 120);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    if !body["summary"].is_object() {
        // Absence is never a negative: an answer with no audit in it is not
        // "no clusters", it is an answer we cannot read.
        ui::failed("the gateway answered without a cluster audit", Some("noo graph stats"));
        return Ok(1);
    }
    print!("{}", render_cluster_audit(&body, AUDIT_TOP));
    let mut next: Vec<(&str, &str)> = Vec::new();
    if body["caveats"].as_array().is_some_and(|c| !c.is_empty()) {
        next.push(("noo rag docs --untagged", "the documents with no audience tag: the gap behind a premature measurement"));
        next.push(("noo rag retag", "assign an audience to them (dry-run unless --apply), then audit again"));
    }
    next.push(("noo graph recluster", "rebuild the clusters after retagging (Intelligent tier; minutes)"));
    ui::guide(&next);
    Ok(0)
}

fn count(v: &serde_json::Value) -> String {
    v.as_u64().map(|n| n.to_string()).unwrap_or_else(|| "?".to_string())
}

fn pct(v: &serde_json::Value) -> String {
    v.as_f64().map(|f| format!("{:.0}%", f * 100.0)).unwrap_or_else(|| "?".to_string())
}

/// `{"a": 1, "b": 2}` as `a 1, b 2`, largest first (ties by key).
fn counts_inline(v: &serde_json::Value) -> String {
    let Some(map) = v.as_object() else { return ui::dash().to_string() };
    let mut pairs: Vec<(&String, u64)> = map.iter().map(|(k, n)| (k, n.as_u64().unwrap_or(0))).collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    if pairs.is_empty() {
        return ui::dash().to_string();
    }
    pairs.iter().map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join(", ")
}

/// The human rendering of the audit. Pure: the caller prints it.
fn render_cluster_audit(b: &serde_json::Value, top: usize) -> String {
    let (s, run) = (&b["summary"], &b["run"]);
    let mut out = String::new();
    let right = format!("{} clusters", count(&s["total_clusters"]));
    out.push_str(&format!("{}\n", ui::header("cluster audiences", Some(&right))));

    let reader = &s["reader"];
    let roles: Vec<&str> = reader["roles"]
        .as_array()
        .map(|a| a.iter().filter_map(|r| r.as_str()).collect())
        .unwrap_or_default();
    let cov = &s["coverage"];
    out.push_str(&ui::section("summary"));
    out.push('\n');
    let rows = vec![
        ("mix", counts_inline(&s["by_mix"])),
        (
            "reader sees",
            format!(
                "{} whole · {} partial · {} none  (reader {{{}}}; {} of members readable)",
                count(&reader["whole"]),
                count(&reader["partial"]),
                count(&reader["none"]),
                roles.join(", "),
                pct(&reader["readable_share_of_members"]),
            ),
        ),
        ("tiers per cluster", counts_inline(&s["distinct_tiers_per_cluster"])),
        ("members by tier", counts_inline(&s["members_by_tier"])),
        (
            "single / multi tier",
            format!("{} / {} members", count(&s["single_tier_members"]), count(&s["multi_tier_members"])),
        ),
        (
            "clustered",
            format!(
                "{} of {} entities ({})",
                count(&cov["clustered_entities"]),
                count(&cov["entities_total"]),
                pct(&cov["clustered_share"]),
            ),
        ),
        (
            "untagged only",
            format!(
                "{} members ({} of the clustered)",
                count(&cov["untagged_only_members"]),
                pct(&cov["untagged_only_fraction"]),
            ),
        ),
        (
            "run",
            format!(
                "generation {} · {} meta clusters · {}",
                run["latest_generation"].as_i64().map(|g| g.to_string()).unwrap_or_else(|| "?".into()),
                count(&run["meta_clusters"]),
                run["computed_at"].as_str().unwrap_or("time not stored"),
            ),
        ),
    ];
    out.push_str(&ui::kv(&rows));

    if let Some(caveats) = b["caveats"].as_array().filter(|c| !c.is_empty()) {
        out.push_str(&ui::section("caveats"));
        out.push('\n');
        for c in caveats.iter().filter_map(|c| c.as_str()) {
            out.push_str(&format!("{}\n", ui::status_line(ui::Glyph::Warn, c)));
        }
    }

    let empty = Vec::new();
    let clusters = b["clusters"].as_array().unwrap_or(&empty);
    if clusters.is_empty() {
        out.push_str(&format!("\n{}\n", ui::muted("no clusters")));
        return out;
    }
    let shown = clusters.len().min(top);
    out.push_str(&ui::section(&format!("largest {shown} clusters")));
    out.push('\n');
    let rows: Vec<Vec<String>> = clusters
        .iter()
        .take(top)
        .map(|c| {
            vec![
                truncate(c["name"].as_str().unwrap_or("?"), 36),
                count(&c["member_count"]),
                c["mix"].as_str().unwrap_or("?").to_string(),
                counts_inline(&c["tiers"]),
                format!(
                    "{} {}",
                    c["reader_visibility"].as_str().unwrap_or("?"),
                    pct(&c["readable_share"]),
                ),
            ]
        })
        .collect();
    out.push_str(&ui::table(
        &[Col::left("cluster"), Col::right("members"), Col::left("mix"), Col::left("tiers"), Col::left("reader")],
        &rows,
    ));
    if b["truncated"].as_bool() == Some(true) {
        out.push_str(&format!(
            "{}\n",
            ui::muted("the gateway capped its list; the summary above covers every cluster")
        ));
    }
    out
}

/// What `noo graph entity-cleanup` was asked.
#[derive(Debug, PartialEq)]
struct CleanupOpts {
    apply: bool,
    yes: bool,
    examples: u64,
    max_delete: Option<u64>,
}

/// The gateway's own bounds (`knowledge::entity_cleanup_request`).
const CLEANUP_MAX_EXAMPLES: u64 = 200;
const CLEANUP_MAX_DELETE: u64 = 5000;

fn parse_cleanup_opts(args: &[String]) -> Result<CleanupOpts, String> {
    let mut o = CleanupOpts { apply: false, yes: false, examples: 20, max_delete: None };
    let mut iter = args.iter();
    let num = |flag: &str, v: Option<&String>| -> Result<u64, String> {
        v.ok_or_else(|| format!("{flag} needs a number"))?
            .parse::<u64>()
            .map_err(|_| format!("{flag} needs a whole number"))
    };
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--apply" => o.apply = true,
            "--yes" | "-y" => o.yes = true,
            "--examples" => o.examples = num("--examples", iter.next())?,
            "--max-delete" => o.max_delete = Some(num("--max-delete", iter.next())?),
            other => return Err(format!("unknown option {other}")),
        }
    }
    if o.examples > CLEANUP_MAX_EXAMPLES {
        return Err(format!("--examples is at most {CLEANUP_MAX_EXAMPLES}"));
    }
    if let Some(m) = o.max_delete {
        if m == 0 || m > CLEANUP_MAX_DELETE {
            return Err(format!("--max-delete is from 1 to {CLEANUP_MAX_DELETE}"));
        }
    }
    Ok(o)
}

/// The request body. `apply` is always sent explicitly, so a dry run is a
/// stated `false` and never an omission.
fn cleanup_body(apply: bool, o: &CleanupOpts) -> serde_json::Value {
    let mut b = serde_json::json!({"apply": apply, "examples": o.examples});
    if let Some(m) = o.max_delete {
        b["max_delete"] = serde_json::json!(m);
    }
    b
}

/// The report the worker returns, as the operator reads it: the counts, then
/// the most-connected junk. Pure so a test can pin it.
fn render_cleanup_report(r: &serde_json::Value) -> String {
    let n = |k: &str| r[k].as_u64().unwrap_or(0);
    let mut rows: Vec<(&str, String)> = vec![
        ("scanned", format!("{} entities", n("scanned"))),
        ("junk", format!("{} entities", n("junk"))),
        ("with edges", format!("{} entities ({} edge rows)", n("with_edges"), n("edge_rows"))),
        ("with mentions", format!("{} entities ({} mention rows)", n("with_mentions"), n("mention_rows"))),
        ("in clusters", format!("{} entities ({} membership rows)", n("in_clusters"), n("cluster_rows"))),
    ];
    for (key, label) in [("by_reason", "by rule"), ("by_type", "by type")] {
        if let Some(m) = r[key].as_object() {
            let mut parts: Vec<String> = m.iter().map(|(k, v)| format!("{k} {v}")).collect();
            parts.sort();
            if !parts.is_empty() {
                rows.push((label, parts.join(", ")));
            }
        }
    }
    let mut out = ui::kv(&rows);
    if let Some(ex) = r["examples"].as_array().filter(|e| !e.is_empty()) {
        let table: Vec<Vec<String>> = ex
            .iter()
            .map(|e| {
                vec![
                    truncate(e["name"].as_str().unwrap_or("?"), 32),
                    e["type"].as_str().unwrap_or("?").to_string(),
                    e["edges"].as_u64().unwrap_or(0).to_string(),
                    e["mentions"].as_u64().unwrap_or(0).to_string(),
                    e["clusters"].as_u64().unwrap_or(0).to_string(),
                ]
            })
            .collect();
        out.push_str(&ui::section(&format!("most connected junk ({} shown)", ex.len())));
        out.push('\n');
        out.push_str(&ui::table(
            &[Col::left("name"), Col::left("type"), Col::right("edges"), Col::right("mentions"), Col::right("clusters")],
            &table,
        ));
    }
    out
}

/// One request that the gateway may answer `200` (finished in its wait) or
/// `202` (a handle): followed to the end, so it reads as one foreground
/// command. `Err` carries the exit code, the failure already reported.
fn run_cleanup_op(g: &Globals, body: &serde_json::Value, what: &str) -> Result<serde_json::Value, i32> {
    let started = post_json(g, "/api/v1/graph/entity-cleanup", body, true, 30);
    // The run is allowed 600s worker-side (+30s); wait a little longer than that.
    let out = super::ops::settle(g, started, what, 660)?;
    refuse_error_body(g, &out, what).map(|()| out)
}

/// A body that carries an `error` is a failure, whatever status it came with.
///
/// `settle` and `post_json` already turn a non-2xx answer and a failed or
/// cancelled operation into a reported failure and a non-zero exit; this is the
/// last gap: a `200` whose body is the worker's refusal (`{"error": ...}`), which
/// would otherwise fall through to the success branch and print "staged and
/// removed 0". The gateway's own words are shown, never a paraphrase. `Err` is the
/// exit code; the failure is already reported.
fn refuse_error_body(g: &Globals, body: &serde_json::Value, what: &str) -> Result<(), i32> {
    let Some(err) = body["error"].as_str().filter(|e| !e.is_empty()) else {
        return Ok(());
    };
    if g.json {
        println!("{body}");
    } else {
        ui::failed(&format!("{what} failed: {err}"), Some("noo ops list"));
    }
    Err(1)
}

/// `noo graph entity-cleanup [--apply] [--examples N] [--max-delete N] [--yes]` —
/// POST /api/v1/graph/entity-cleanup (admin only).
///
/// Clears the junk entities (`a`, `x_t`, `theta`, `0.003`) that were stored
/// before trellion learned to refuse them. This is the front door for what
/// was `docker exec noo-trellion trellion entity-cleanup`: the same cleanup,
/// but authorised as an Admin and audited, and run as an operation.
///
/// DRY RUN unless `--apply`: prints the counts and the most-connected examples
/// and changes nothing. `--apply` shows that same plan, asks for confirmation
/// (`--yes` for scripts; `--json` never prompts), then stages every junk entity
/// into the graph prune staging area and deletes it, at most `--max-delete`
/// (default and ceiling 5,000) per run: re-run to continue. Staged entities are
/// restorable for the staging retention window.
pub fn graph_entity_cleanup(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let opts = match parse_cleanup_opts(args) {
        Ok(o) => o,
        Err(msg) => {
            ui::failed(&msg, Some("noo graph entity-cleanup --help"));
            return Ok(2);
        }
    };

    // Always preview first, even for --apply: the operator is shown exactly
    // what they are about to remove, from the same scan.
    if !g.json {
        ui::step("scanning the knowledge graph for junk entities");
    }
    let preview = match run_cleanup_op(g, &cleanup_body(false, &opts), "scanning for junk entities") {
        Ok(b) => b,
        Err(code) => return Ok(code),
    };
    if !opts.apply {
        if g.json {
            println!("{preview}");
            return Ok(0);
        }
        print!("{}", render_cleanup_report(&preview));
        println!();
        ui::done(&format!("{} junk entities found — dry run, nothing was changed", preview["junk"].as_u64().unwrap_or(0)));
        ui::guide(&[("noo graph entity-cleanup --apply", "stage and remove them (restorable for 30 days; asks first)")]);
        return Ok(0);
    }

    let junk = preview["junk"].as_u64().unwrap_or(0);
    if junk == 0 {
        if g.json {
            println!("{preview}");
        } else {
            ui::done("no junk entities; nothing to clean");
        }
        return Ok(0);
    }
    let cap = opts.max_delete.unwrap_or(CLEANUP_MAX_DELETE);
    let this_run = junk.min(cap);
    if !g.json {
        print!("{}", render_cleanup_report(&preview));
        println!();
        if junk > cap {
            ui::warned(&format!("{} of {junk} are over --max-delete {cap}; this run removes {this_run}, run it again for the rest", junk - cap));
        }
    }
    super::confirm_destructive(
        g,
        opts.yes,
        "Stage and remove",
        &format!(
            "{this_run} junk entities ({} edge rows, {} mention rows go with them; restorable for 30 days)",
            preview["edge_rows"].as_u64().unwrap_or(0),
            preview["mention_rows"].as_u64().unwrap_or(0),
        ),
    );

    if !g.json {
        // No claim about what happened: the response decides what is printed next.
        ui::step("removing junk entities");
    }
    let out = match run_cleanup_op(g, &cleanup_body(true, &opts), "removing junk entities") {
        Ok(b) => b,
        Err(code) => return Ok(code),
    };
    if g.json {
        println!("{out}");
        return Ok(0);
    }
    let run_id = out["run_id"].as_str().unwrap_or("?");
    ui::done(&format!("staged and removed {} junk entities (run {run_id})", out["staged"].as_u64().unwrap_or(0)));
    let over = out["skipped_over_cap"].as_u64().unwrap_or(0);
    if over > 0 {
        ui::warned(&format!("{over} more are over the cap; run `noo graph entity-cleanup --apply` again to continue"));
    }
    ui::guide(&[
        (&format!("noo graph prune restore --run {run_id}"), "undo it: bring this run's entities back (restorable for 30 days)"),
        ("noo graph recluster", "rebuild the clusters without the removed entities (Intelligent tier; minutes)"),
        ("noo graph stats", "entity and edge totals after the cleanup"),
    ]);
    Ok(0)
}

/// `noo graph prune restore --run <id>` — POST /api/v1/graph/prune/restore {run_id}.
///
/// Brings back everything one cleanup run staged (the run id is printed by
/// `noo graph entity-cleanup --apply`). The gateway restores up to 500 per call
/// and says how many remain; this calls again until none do. Operator and above.
pub fn graph_prune_restore(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut run: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--run" => run = Some(iter.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    let Some(run) = run else {
        ui::failed("give --run <id> (the run id `noo graph entity-cleanup --apply` printed)", Some("noo graph prune restore --help"));
        return Ok(2);
    };
    let (mut restored, mut skipped, mut edges, mut mentions) = (0u64, 0u64, 0u64, 0u64);
    // 5,000 staged per run / 500 per call = 10 calls; the bound is a guard, not a cap.
    for _ in 0..40 {
        let out = post_json(g, "/api/v1/graph/prune/restore", &serde_json::json!({"run_id": run}), true, 120);
        if let Some(err) = out["error"].as_str() {
            ui::failed(err, None);
            return Ok(1);
        }
        restored += out["restored"].as_u64().unwrap_or(0);
        skipped += out["not_restored"].as_u64().unwrap_or(0);
        edges += out["edges_restored"].as_u64().unwrap_or(0);
        mentions += out["mentions_restored"].as_u64().unwrap_or(0);
        let remaining = out["remaining"].as_i64().unwrap_or(0);
        if remaining <= 0 || out["restored"].as_u64().unwrap_or(0) == 0 {
            break;
        }
    }
    if g.json {
        println!("{}", serde_json::json!({"run_id": run, "restored": restored, "not_restored": skipped, "edges_restored": edges, "mentions_restored": mentions}));
        return Ok(0);
    }
    if restored == 0 {
        ui::warned(&format!("nothing to restore for run {run} (already restored, past retention, or no such run)"));
        return Ok(0);
    }
    ui::done(&format!("restored {restored} entities ({edges} edges, {mentions} mentions) from run {run}"));
    if skipped > 0 {
        ui::warned(&format!("{skipped} could not be restored; see the gateway log"));
    }
    ui::guide(&[("noo graph recluster", "rebuild the clusters to include them again (Intelligent tier; minutes)")]);
    Ok(0)
}

#[cfg(test)]
mod cluster_audit_tests {
    use super::*;
    use serde_json::json;

    fn sample() -> serde_json::Value {
        json!({
            "run": {"latest_generation": 1, "computed_at": "2026-10-03T16:14:00+00:00", "meta_clusters": 9},
            "summary": {
                "total_clusters": 3,
                "by_mix": {"mixed": 1, "pure:company": 1, "pure:untagged": 1},
                "reader": {"roles": ["company", "system"], "whole": 1, "partial": 1, "none": 1,
                           "readable_share_of_members": 0.5},
                "distinct_tiers_per_cluster": {"1": 2, "3": 1},
                "members_by_tier": {"company": 5, "user:*": 3, "untagged": 4},
                "single_tier_members": 10, "multi_tier_members": 1,
                "coverage": {"entities_total": 18, "clustered_entities": 11, "clustered_share": 0.6111,
                             "untagged_only_members": 4, "untagged_only_fraction": 0.3636,
                             "no_provenance_members": 1},
            },
            "caveats": ["36% of clustered entities come only from untagged documents"],
            "clusters": [
                {"name": "Robotics and AI Systems", "member_count": 4, "mix": "mixed",
                 "tiers": {"company": 2, "user:*": 3}, "reader_visibility": "partial", "readable_share": 0.5},
                {"name": "Docs", "member_count": 3, "mix": "pure:company",
                 "tiers": {"company": 3}, "reader_visibility": "whole", "readable_share": 1.0},
                {"name": "Old notes", "member_count": 4, "mix": "pure:untagged",
                 "tiers": {"untagged": 4}, "reader_visibility": "none", "readable_share": 0.0},
            ],
            "truncated": false,
        })
    }

    #[test]
    fn the_summary_clusters_and_caveats_are_all_rendered() {
        let out = render_cluster_audit(&sample(), 20);
        for want in [
            "3 clusters",
            "mixed 1, pure:company 1, pure:untagged 1",
            "1 whole · 1 partial · 1 none",
            "{company, system}",
            "50% of members readable",
            "1 2, 3 1",
            "11 of 18 entities (61%)",
            "4 members (36% of the clustered)",
            "generation 1 · 9 meta clusters · 2026-10-03T16:14:00+00:00",
            "Caveats",
            "36% of clustered entities come only from untagged documents",
            "Robotics and AI Systems",
            "pure:untagged",
            "user:* 3, company 2",
            "partial 50%",
            "whole 100%",
            "none 0%",
        ] {
            assert!(out.contains(want), "missing `{want}` in:\n{out}");
        }
    }

    #[test]
    fn the_cluster_list_is_capped_at_the_top_n() {
        let out = render_cluster_audit(&sample(), 2);
        assert!(out.contains("Robotics and AI Systems") && out.contains("Docs"));
        assert!(!out.contains("Old notes"), "{out}");
        assert!(out.contains("Largest 2 Clusters"), "{out}");
    }

    #[test]
    fn a_field_the_gateway_did_not_send_is_unknown_not_zero() {
        let mut b = sample();
        b["summary"]["coverage"] = json!({});
        b["run"] = json!({});
        let out = render_cluster_audit(&b, 20);
        assert!(out.contains("? of ? entities"), "{out}");
        assert!(out.contains("generation ? · ? meta clusters · time not stored"), "{out}");
    }

    #[test]
    fn no_clusters_says_so() {
        let mut b = sample();
        b["clusters"] = json!([]);
        assert!(render_cluster_audit(&b, 20).contains("no clusters"));
    }
}

#[cfg(test)]
mod navigate_tests {
    use super::navigate_body;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_question_is_the_query_and_flags_become_fields() {
        let b = navigate_body(&a(&["why", "does", "it", "fail", "-H", "3", "-s", "e1", "--seed", "e2"])).unwrap();
        assert_eq!(b["query"], "why does it fail");
        assert_eq!(b["max_hops"], 3);
        assert_eq!(b["seed_entities"], serde_json::json!(["e1", "e2"]));
        let plain = navigate_body(&a(&["q"])).unwrap();
        assert!(plain.get("max_hops").is_none() && plain.get("seed_entities").is_none());
    }

    #[test]
    fn no_question_or_a_bad_flag_is_a_usage_error() {
        assert!(navigate_body(&a(&[])).is_none());
        assert!(navigate_body(&a(&["-H", "2"])).is_none());
        assert!(navigate_body(&a(&["q", "--bogus"])).is_none());
        assert!(navigate_body(&a(&["q", "-H", "many"])).is_none());
        assert!(navigate_body(&a(&["q", "-s"])).is_none());
    }
}

#[cfg(test)]
mod entity_cleanup_tests {
    use super::*;
    use serde_json::json;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn report() -> serde_json::Value {
        json!({
            "dry_run": true, "scanned": 1200, "junk": 3, "with_edges": 2, "edge_rows": 9,
            "with_mentions": 3, "mention_rows": 14, "in_clusters": 1, "cluster_rows": 1,
            "by_reason": {"math_symbol": 2, "bare_number": 1}, "by_type": {"concept": 3},
            "examples": [
                {"name": "theta", "type": "concept", "reason": "math_symbol", "edges": 7, "mentions": 8, "clusters": 1},
                {"name": "0.003", "type": "concept", "reason": "bare_number", "edges": 2, "mentions": 4, "clusters": 0},
            ],
            "staged": 0, "skipped_over_cap": 0, "run_id": null,
        })
    }

    #[test]
    fn no_flags_is_a_dry_run_that_sends_apply_false_explicitly() {
        let o = parse_cleanup_opts(&a(&[])).unwrap();
        assert!(!o.apply && !o.yes);
        assert_eq!(cleanup_body(false, &o), json!({"apply": false, "examples": 20}));
        let o = parse_cleanup_opts(&a(&["--apply", "--yes", "--examples", "5", "--max-delete", "100"])).unwrap();
        assert!(o.apply && o.yes);
        assert_eq!(cleanup_body(true, &o), json!({"apply": true, "examples": 5, "max_delete": 100}));
    }

    #[test]
    fn bounds_and_unknown_flags_are_refused_before_any_request() {
        for bad in [&["--examples", "201"][..], &["--max-delete", "0"], &["--max-delete", "5001"], &["--max-delete"], &["--examples", "x"], &["--bogus"]] {
            assert!(parse_cleanup_opts(&a(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_dry_run_rendering_has_the_counts_and_the_examples_table() {
        let out = render_cleanup_report(&report());
        for want in [
            "1200 entities", "3 entities", "2 entities (9 edge rows)", "3 entities (14 mention rows)",
            "1 entities (1 membership rows)", "bare_number 1, math_symbol 2", "concept 3",
            "Most Connected Junk (2 Shown)", "NAME", "TYPE", "EDGES", "MENTIONS", "CLUSTERS", "theta", "0.003",
        ] {
            assert!(out.contains(want), "missing `{want}` in:\n{out}");
        }
        // most-connected first, as the worker sent them
        assert!(out.find("theta").unwrap() < out.find("0.003").unwrap());
    }

    #[test]
    fn a_report_with_no_examples_renders_counts_only() {
        let mut r = report();
        r["examples"] = json!([]);
        let out = render_cleanup_report(&r);
        assert!(!out.contains("Most Connected Junk"), "{out}");
    }

    /// `--apply` must reach `confirm_destructive` BEFORE the apply request is
    /// sent, and the preview request before that. Pinned on the source because
    /// the command talks to a live gateway.
    #[test]
    fn apply_confirms_before_it_sends_the_apply_request() {
        let src = include_str!("graph.rs");
        let body = &src[src.find("pub fn graph_entity_cleanup").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        let preview = body.find("cleanup_body(false").expect("a preview request");
        let confirm = body.find("confirm_destructive(").expect("--apply must confirm");
        let apply = body.find("cleanup_body(true").expect("an apply request");
        assert!(preview < confirm && confirm < apply, "preview, then confirm, then apply");
        assert!(!body[..confirm].contains("cleanup_body(true"));
    }

    #[test]
    fn the_restore_hint_names_the_real_command_with_the_run_id() {
        let src = include_str!("graph.rs");
        let body = &src[src.find("pub fn graph_entity_cleanup").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        assert!(body.contains("noo graph prune restore --run {run_id}"), "the undo hint is the real command");
        assert!(!body.contains("to undo: POST"), "no raw-route hint any more");
    }
}
