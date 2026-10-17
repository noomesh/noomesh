// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster …` — cluster node inventory + desired-state control plane
//! (Rust gateway routes in `routes/cluster.rs`) plus the agent-relevant
//! SSH commands (`exec`, `logs`), which resolve the node via the gateway
//! and spawn `ssh` with INHERITED stdio — fixing the Python versions'
//! swallowed-stdout / 30s-timeout behavior — and propagate the remote
//! exit code (never 0 on failure).
//!
//! Ported: status, desired, place, unplace, exec, logs, restart-agent, up,
//! down, scale (the destructive pair uses the agent-first confirm contract
//! in `commands::confirm_destructive` — `--yes` skips, `--json`/non-TTY
//! never block on a prompt).
//!
//! Batch 3 (this pass):
//!   HTTP/local — init-secret (local `token_urlsafe(32)`,
//!   no gateway), assign, set-config, clear-cooldowns, add-companion,
//!   add-monitor.
//!   Retired stubs (name their replacements rather than 404) — clean-node,
//!   sync-models.
//!
//!   This module spawns no `ssh` and no `scp`. It was the last one in the
//!   crate that did; `tests/test_no_controller_ssh.py` keeps it that way.
//!
//! The provisioning surface (auto-place, place-model, reconcile-models,
//! sync-images, upgrade-agents, set-primary, mint-join-key, ship-model,
//! clean) is now native too — see `cluster_provision.rs`.
//!
//! SSH user resolution (superset of Python's `_resolve_ssh_user`):
//! `--user` override → node's `ssh_user` from the gateway → the YAML
//! cluster inventory (`~/.config/noo/cluster-inventory.yaml`, concrete
//! hosts then subnets) → `ansible/inventory/hosts` `ansible_user=` (extra
//! fallback the Python exec lacks — without it host8 resolves to the
//! local user and fails auth) → none (ssh uses the local username).

use std::path::PathBuf;
use std::process::Command;

use super::truncate;
use crate::http::{
    delete_json, get_json, post_json, post_json_try, put_json,
};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo cluster status` — node inventory from /api/cluster/nodes.
/// `--watch [SECS]` (default 2): redraw on a TTY until Ctrl-C. Rejected
/// under `--json`/`--quiet` and off a terminal, where it makes no sense.
pub fn cluster_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let Ok((rest, watch)) = crate::ui::take_watch(args) else { return Err(Unhandled) };
    let Some(secs) = watch else { return cluster_status_once(g, &rest) };
    if g.json || g.quiet || !crate::ui::styled() {
        crate::output::fail(g.json, crate::output::ExitCode::Usage, "usage",
            "--watch needs an interactive terminal (not --json/--quiet or a pipe)", None);
    }
    Ok(crate::ui::watch_loop(secs, || cluster_status_once(g, &rest).unwrap_or(2)))
}

fn cluster_status_once(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/cluster/nodes", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }

    let empty = Vec::new();
    let nodes = body["nodes"].as_array().unwrap_or(&empty);
    if nodes.is_empty() {
        println!("{}", ui::muted("no nodes"));
        return Ok(0);
    }
    println!("{}", ui::header("cluster", Some(&format!("{} nodes", nodes.len()))));
    println!("{}", ui::section("nodes"));
    // "can-run", not "backends": the column is the node's ADVERTISED
    // capability set, and the old name read as running services ("why does
    // host1 have all those backends?" — finding #50).
    let mut deaf: Vec<(&str, &str)> = Vec::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut harness_refusals: Vec<(String, String)> = Vec::new();
    // Nodes whose GPU went to work outside noomesh (yielded or held): online,
    // by design, and the reason their GPU backend is missing from `running`.
    let mut gpu_notes: Vec<String> = Vec::new();
    for n in nodes {
        if let Some(note) = super::cluster_gpu::gpu_status_note(n) {
            gpu_notes.push(note);
        }
        let id = n["id"].as_str().unwrap_or("?");
        let status = n["status"].as_str().unwrap_or("?");
        // The node's own report of its NATS connection. `?` means the node
        // never sent one (an older agent build) — which is not the same as
        // "connected", and must not be printed as if it were.
        let bus = n["nats_state"].as_str().unwrap_or("?");
        if bus != "connected" && bus != "?" {
            deaf.push((id, n["nats_state_detail"].as_str().unwrap_or("no detail")));
        }
        // WHICH principal the node authenticates as. "node" = its own
        // per-principal credential; "shared" = the fleet-wide fallback;
        // "anonymous" = none. "?" = the agent does not report it, which is
        // NOT the same as shared and must not be shown as if it were.
        //
        // Two nodes on different credentials look identical in the bus column
        // — both "connected". Telling them apart was the whole diagnosis of
        // the 2026-09-05 gossip outage, where only the nodes holding a
        // per-principal credential had silently stopped announcing.
        let cred = n["nats_role"].as_str().unwrap_or("?");
        let load = n["current_load"].as_f64().unwrap_or(0.0);
        let backends: Vec<&str> = n["capabilities"]["backends"]
            .as_array()
            .map(|a| a.iter().filter_map(|b| b.as_str()).collect())
            .unwrap_or_default();
        // Operator ask 2026-08-27 (the #50 conversation's other half):
        // capability said what a node COULD host; this says what it IS
        // hosting. The agent reports it every beat; empty = idle.
        // A `*` marks a backend served NATIVELY — found by the agent, not
        // started by it, and not reconciled against a placement. Same word,
        // different relationship; the legend below says so.
        // The model beside the backend: the
        // agent reports `backend → model` every beat and this column dropped
        // the model, so the one fleet-wide view could not answer "what is
        // deployed where" — `harrier` on host2 and `llama3.2:3b` on host6
        // both read as a bare `ollama`.
        let runtimes = n["backend_runtimes"].as_object();
        let running: Vec<String> = n["running_backends"]
            .as_object()
            .map(|m| m.iter().map(|(k, v)| {
                let native = matches!(
                    runtimes.and_then(|r| r.get(k)).and_then(|r| r.as_str()),
                    Some("native")
                );
                let cell = running_cell(k, v.as_str(), native);
                // The container runs but the node reports it does not hold
                // the placed model.
                if backend_model_missing(n, k) { format!("{cell} (model missing)") } else { cell }
            }).collect())
            .unwrap_or_default();
        let glyph = match status {
            "online" | "healthy" | "ready" | "running" => Glyph::Ok,
            "offline" | "unreachable" | "down" | "failed" => Glyph::Err,
            _ => Glyph::Warn,
        };
        rows.push(vec![
            ui::glyph_cell(glyph),
            id.to_string(),
            ui::state(status),
            if bus == "connected" { ui::state("connected") } else { ui::warn(bus) },
            match cred {
                "node" => ui::state("node"),
                // A shared or absent credential is weaker than the fleet's
                // intent, so neither is printed as if it were fine.
                "shared" => ui::warn("shared"),
                "anonymous" => ui::warn("anon"),
                other => ui::muted(other),
            },
            format!("{:.0}%", load * 100.0),
            running.join(","),
            harness_cell(n),
            // Derived by the gateway from the node's ROLE placements
            // (chat:gemma4:26b · embed:harrier); `-` for an older gateway
            // that does not send the field, or a node with no placements.
            capabilities_cell(n),
            backends.join(","),
        ]);
        // The REASON a harness is not running is the half a cell cannot
        // carry, and it is what an operator acts on. It was never on this
        // screen: `desired: running` read as running for half an hour while
        // a harness failed to start every five minutes.
        if let Some(r) = n["reconcile_refusals"].as_array().and_then(|rs| {
            rs.iter().find(|r| r["target"] == "harness").and_then(|r| r["reason"].as_str())
        }) {
            harness_refusals.push((id.to_string(), truncate(r, 140)));
        }
    }
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::left("node"),
                Col::left("status"),
                Col::left("bus"),
                Col::left("cred"),
                Col::right("load"),
                Col::left("running"),
                Col::left("harness"),
                Col::left("capabilities"),
                Col::left("can-run"),
            ],
            &rows,
        )
    );
    if !harness_refusals.is_empty() {
        println!();
        for (id, reason) in &harness_refusals {
            println!("{}", ui::status_line(Glyph::Warn, &format!("{id} harness: {reason}")));
        }
    }
    if !gpu_notes.is_empty() {
        println!();
        for note in &gpu_notes {
            println!("{}", ui::status_line(Glyph::Warn, note));
        }
    }
    // A node can be HTTP-alive and bus-deaf at once; jobs dispatched to it
    // strand silently. Say so rather than leaving it to a column nobody reads.
    if !deaf.is_empty() {
        println!();
        for (id, detail) in deaf {
            println!("{}", ui::status_line(Glyph::Warn, &format!("{id} is off the bus: {detail}")));
        }
    }
    println!();
    println!(
        "{}",
        ui::muted("running = backend:model live now (agent-reported; - = idle; * = adopted, not managed: a native process or the controller's own stack) · \
                   can-run = able to host · \
                   cred = bus principal (node = its own, shared = fleet fallback, ? = not reported)")
    );
    ui::guide(&[
        ("noo cluster desired <node>", "the placements and config this node is meant to run"),
        ("noo cluster place <node> <backend> <model>", "assign a model to a node (desired state; the agent keeps it running)"),
        ("noo cluster place-model <model> --apply", "let the scheduler pick the best node for a model"),
    ]);
    Ok(0)
}

/// `noo cluster forget NODE` — agent-less controller-side cleanup: removes
/// the node's DB row + mesh-KV entry so registration is first-contact again.
/// For a node that is already dismantled or unreachable (orphaned teardown,
/// dead hardware) — a LIVE node re-registers on its next heartbeat, so
/// dismantle it first (`noo cluster teardown-node`, or `sudo noo-deenroll`
/// on the box). Same route teardown calls internally; this is the manual
/// door for when teardown never got to run.
///
/// `--purge-tailscale` also deletes the node's device record from the
/// tailnet. Without it a dead node's device stayed forever: `teardown-node`
/// keeps the device until the node has collected its teardown (it needs the
/// tailnet to do so), a dead node never collects it, and `forget` did not
/// touch the tailnet at all — so the next enrollment under the same name
/// registered as `<name>-1`.
pub fn cluster_forget(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (node, purge_ts, yes) = parse_forget_args(args).ok_or(Unhandled)?;
    let node = &node;
    // Rows, enrollments and (optionally) the tailnet device go; only the PKI
    // directory is archived. Ask first, like `cluster down`.
    super::confirm_destructive(g, yes, "forget node", node);
    // Read the tailnet IP BEFORE the forget: forgetting deletes the row it
    // lives in.
    let ts_ip = if purge_ts {
        crate::commands::security_local::registered_tailnet_ip(g, node)
    } else {
        None
    };
    let body = delete_json(
        g,
        &format!("/api/cluster/nodes/{}/forget", super::urlencode(node)),
        true,
        15,
    );
    // Forgetting a node removed its DB row and left its key material on the
    // controller's disk forever. That material then read as a NODE to
    // anything that enumerated `<pki>/nodes/*` — `noo security pki
    // rotate-signing-key` reported `host8`, forgotten months earlier, as a
    // straggler that could never be delivered to (2026-09-12). The registry
    // is the authority and the readers were fixed, but leaving the material
    // behind is what created the disagreement, so close it here too.
    //
    // ARCHIVED, not deleted. This is a private key: `forget` is a
    // registration operation and must not be a shredder, and an operator who
    // forgets the wrong node should be able to undo it. The archive is named
    // with a dot prefix and a timestamp so no enumerator can mistake it for
    // a node.
    let archived = archive_node_pki(node);
    let ts_outcome = purge_ts
        .then(|| crate::commands::security_local::delete_tailnet_device(g, node, ts_ip.as_deref()));
    if g.json {
        // Merge rather than print the gateway's body verbatim: a scripted
        // caller that cleans up after a forget needs to know a path was
        // moved on the controller's disk.
        let mut doc = body.clone();
        if let Some(obj) = doc.as_object_mut() {
            obj.insert("pki_archived".into(), match &archived {
                Some(p) => serde_json::Value::String(p.display().to_string()),
                None => serde_json::Value::Null,
            });
            if let Some(t) = &ts_outcome {
                obj.insert("tailnet_device".into(), serde_json::Value::String(t.clone()));
            }
        }
        println!("{doc}");
        return Ok(0);
    }
    let revoked = body.get("enrollments_revoked").and_then(|v| v.as_u64()).unwrap_or(0);
    let config_rows = body.get("config_rows").and_then(|v| v.as_u64()).unwrap_or(0);
    let placements = body.get("placements").and_then(|v| v.as_u64()).unwrap_or(0);
    ui::done(&format!(
        "{node} forgotten — node row + mesh entry removed, {config_rows} config row(s) and \
         {placements} placement(s) dropped, {revoked} enrollment(s) revoked; registration is first-contact again"
    ));
    if let Some(path) = archived {
        println!("  {}", ui::muted(&format!(
            "its key material was archived to {} — delete it when you are sure, or move it back to restore",
            path.display()
        )));
    }
    match ts_outcome {
        Some(t) => println!("  {}", ui::muted(&format!("tailnet: {t}"))),
        None => println!("  {}", ui::muted(
            "its tailnet device was kept — `--purge-tailscale` removes it, or delete it in the Tailscale console",
        )),
    }
    Ok(0)
}

/// `<node> [--purge-tailscale]`, in either order; anything else is a usage error.
fn parse_forget_args(args: &[String]) -> Option<(String, bool, bool)> {
    let mut node = None;
    let mut purge_ts = false;
    let mut yes = false;
    for a in args {
        match a.as_str() {
            "--purge-tailscale" => purge_ts = true,
            "-y" | "--yes" => yes = true,
            s if s.starts_with('-') => return None,
            s if node.is_none() => node = Some(s.to_string()),
            _ => return None,
        }
    }
    node.map(|n| (n, purge_ts, yes))
}

/// Move `<pki>/nodes/<node>` aside, returning where it went.
///
/// `None` when there was nothing there, which is the common case: the CLI
/// runs on plenty of boxes that are not the controller that issued the cert.
/// A failure to move is NOT fatal — the node is already forgotten by the
/// time this runs, and the readers no longer trust the directory anyway.
fn archive_node_pki(node: &str) -> Option<std::path::PathBuf> {
    // Refuse anything that is not a plain node name before it reaches a
    // filesystem path. `forget` takes its argument from argv.
    if node.is_empty()
        || !node.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        || node.starts_with('.')
    {
        return None;
    }
    let dir = crate::pki::pki_dir().join("nodes").join(node);
    if !dir.is_dir() {
        return None;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dest = crate::pki::pki_dir().join(format!(".forgotten-{node}-{ts}"));
    std::fs::rename(&dir, &dest).ok().map(|()| dest)
}

/// `noo cluster desired NODE` — GET /api/cluster/nodes/{node}/desired-config.
/// The DB-backed desired state the node-agent reconciles toward every 5 min.
/// `noo cluster show <node>` — everything known about ONE node, in one place.
///
/// `cluster status` is the fleet at a glance and cannot carry per-node depth;
/// `cluster desired` shows the DB config row and says "no config row" for a
/// node that is running perfectly well. Neither answered the questions that
/// actually came up: what memory does this box really have, which agent build
/// is it running, and does its declared tier still match what its hardware
/// says.
///
/// That gap had a cost. On 2026-09-05 a release reached no node — every bundle
/// applied `exit 0` while installing the previous release's agent — and the
/// only way to see it was to pipe `--json` and read `app_version` by eye.
/// Agent version beside stack version is the first row here for that reason.
pub fn cluster_show(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [node] = args else { return Err(Unhandled) };
    if node.starts_with('-') {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/cluster/nodes", true, 10);
    let empty = vec![];
    let nodes = body["nodes"].as_array().unwrap_or(&empty);
    let Some(n) = nodes.iter().find(|n| n["id"].as_str() == Some(node.as_str())) else {
        if g.json {
            println!("{}", serde_json::json!({"error": "not_found", "node": node}));
            return Ok(1);
        }
        println!("{}", ui::status_line(Glyph::Err, &format!("{node} is not registered")));
        ui::guide(&[
            ("noo cluster status", "lists the nodes the controller knows about"),
            ("noo cluster bootstrap-token create --node <name>", "starts an enrollment for a new node"),
        ]);
        return Ok(1);
    };
    if g.json {
        println!("{n}");
        return Ok(0);
    }

    let dash = ui::dash().to_string();
    let caps = &n["capabilities"];
    let str_of = |v: &serde_json::Value| v.as_str().unwrap_or(&dash).to_string();

    println!("{}", ui::header(node, Some("node detail")));

    // ── identity ────────────────────────────────────────────────────────
    // Declared vs DERIVED tier, side by side. The gateway re-derives tier
    // from live heartbeats every tick, but the declared value only changes
    // when a bundle re-renders the agent env — and node_tier_drift is
    // disarmed by default, so a disagreement is logged and nothing else.
    // host6 declared 4 while deriving 2 on a 24 GB Mac, and no view showed
    // both numbers.
    let declared = n["tier"].as_i64().map(|t| t.to_string()).unwrap_or(dash.clone());
    let derived = n["derived_tier"].as_i64().map(|t| t.to_string());
    let tier_cell = match &derived {
        Some(d) if *d != declared => format!("{declared} → {d} {}",
            ui::warn("(derived; declared is stale — `noo cluster provision <node> <tier>`)")),
        _ => declared.clone(),
    };
    println!("{}", ui::section("Identity"));
    println!("{}", ui::kv(&[
        ("status", format!("{} {}", str_of(&n["status"]), ui::muted(&str_of(&n["status_detail"])))),
        ("tier", tier_cell),
        ("agent", str_of(&n["app_version"])),
        ("address", str_of(&n["ip_address"])),
        ("last beat", str_of(&n["last_heartbeat"])),
    ]));

    // ── hardware ────────────────────────────────────────────────────────
    // MEASURED, not declared. `vram` on a unified-memory box is the GPU's
    // addressable share of system RAM, not a discrete pool — the qualifier
    // is printed beside it so the number is not misread.
    let unified = caps["unified_memory"].as_bool().unwrap_or(false);
    let vram = caps["vram_gb"].as_f64();
    let vram_cell = match vram {
        Some(v) if unified => format!("{v:.0} GB {}", ui::muted("(unified — the GPU's share of system RAM)")),
        Some(v) if v > 0.0 => format!("{v:.0} GB {}", ui::muted("(dedicated)")),
        Some(_) => format!("{} {}", ui::dash(), ui::muted("(no GPU memory reported)")),
        None => dash.clone(),
    };
    println!("{}", ui::section("Hardware"));
    println!("{}", ui::kv(&[
        ("ram", caps["ram_gb"].as_f64().map(|v| format!("{v:.0} GB")).unwrap_or(dash.clone())),
        ("gpu memory", vram_cell),
        ("gpu api", str_of(&caps["gpu_api"])),
        ("gpu model", str_of(&n["gpu_model"])),
        ("cpu", caps["cpu_cores"].as_i64().map(|c| format!("{c} cores")).unwrap_or(dash.clone())),
        ("platform", format!("{}/{}", str_of(&caps["os"]), str_of(&caps["arch"]))),
        ("self node", match n["self_node"].as_bool() {
            Some(true) => "yes — the controller's own device (its ollama is the stack's, adopted)".to_string(),
            Some(false) => "no".to_string(),
            None => ui::muted("not reported (agent predates this release)").to_string(),
        }),
    ]));

    // ── bus ─────────────────────────────────────────────────────────────
    // The principal matters as much as the state: a node deliberately on the
    // shared fleet pair and one whose per-principal credential never arrived
    // both report connected, and telling them apart was the whole diagnosis
    // of a fleet-wide gossip outage.
    let bus = &n["nats_status"];
    let cred = match bus["role"].as_str() {
        Some("node") => "node (its own per-principal credential)".to_string(),
        Some("shared") => ui::warn("shared (fleet-wide fallback)").to_string(),
        Some("anonymous") => ui::warn("anonymous (no credential)").to_string(),
        Some(other) => other.to_string(),
        None => format!("{} {}", dash, ui::muted("(this agent build does not report it)")),
    };
    println!("{}", ui::section("Bus"));
    // Everything below is what the NODE said in its LAST heartbeat. The
    // gateway already decides liveness from gossip and puts the verdict in
    // `status`; when that verdict is anything but online, printing
    // "State connected / Job Dispatch bound" as bare fact is fiction — host6
    // showed exactly that for 2h36m while asleep (2026-09-06). Say whose
    // claim it is and when it was made, so a stale snapshot reads as one.
    let node_status = str_of(&n["status"]);
    if !node_status.is_empty() && node_status != "online" {
        println!("  {}", ui::muted(&format!(
            "as reported by the node at its last heartbeat ({}) — the gateway now says: {}",
            str_of(&n["last_heartbeat"]), node_status)));
    }
    println!("{}", ui::kv(&[
        ("state", str_of(&n["nats_state"])),
        ("credential", cred),
        ("principal", str_of(&bus["user"])),
        ("job dispatch", match bus["job_dispatch_bound"].as_bool() {
            Some(true) => "bound".to_string(),
            Some(false) => ui::warn("NOT bound — dispatched jobs will strand").to_string(),
            None => dash.clone(),
        }),
        ("detail", ui::muted(&str_of(&n["nats_state_detail"])).to_string()),
    ]));

    // ── backends ────────────────────────────────────────────────────────
    // WHICH runtime serves each backend, beside the model. "docker" and
    // "native" look identical in running_backends — one word, two
    // relationships — and the difference decides whether a placement can
    // converge. A native backend is one this agent FOUND; it will not be
    // started, stopped or reconciled by the controller.
    let runtimes = n["backend_runtimes"].as_object();
    let running: Vec<String> = n["running_backends"].as_object()
        .map(|m| m.iter().map(|(k, v)| {
            let model = v.as_str().unwrap_or("?");
            match runtimes.and_then(|r| r.get(k)).and_then(|r| r.as_str()) {
                Some("native") => format!("{k}: {model} {}",
                    ui::muted("(native — adopted, not managed by this agent)")),
                Some("stack") => format!("{k}: {model} {}",
                    ui::muted("(the controller's own stack — adopted, not managed by this agent)")),
                // "docker" is the historical default and needs no annotation;
                // an agent that reports nothing is not claimed to be either.
                _ => format!("{k}: {model}"),
            }
        }).collect())
        .unwrap_or_default();
    let can_run: Vec<&str> = caps["backends"].as_array()
        .map(|a| a.iter().filter_map(|b| b.as_str()).collect())
        .unwrap_or_default();
    println!("{}", ui::section("Backends"));
    println!("{}", ui::kv(&[
        ("running", if running.is_empty() { ui::muted("idle").to_string() } else { running.join(", ") }),
        ("can run", if can_run.is_empty() { dash.clone() } else { can_run.join(", ") }),
        ("load", format!("{:.0}%", n["current_load"].as_f64().unwrap_or(0.0) * 100.0)),
    ]));

    // ── roles ───────────────────────────────────────────────────────────
    // What the node SERVES, per role: derived by the gateway from the node's
    // role placements and its heartbeat (one ollama can serve chat AND
    // embed). A placed-but-missing model reads as missing, not as served.
    // The hardware each role runs on and the node's usage profile live in
    // the desired state; a failed read leaves them off rather than failing
    // the screen.
    let desired = crate::http::get_json_try(g, &format!("/api/cluster/nodes/{}/desired-config", super::urlencode(node)), true, 10).ok();
    if let Some(d) = desired.as_ref().filter(|d| d["node"].is_object()) {
        println!("{}", ui::kv(&[("usage", usage_cell(&d["node"]))]));
    }
    print!("{}", role_capabilities_section_with(n, desired.as_ref().map(|d| &d["placements"])));

    ui::guide(&[
        (&format!("noo cluster desired {node}"), "the DB config row and placements this node converges to"),
        (&format!("noo cluster place {node} <backend> <model>"), "give it something to run"),
        (&format!("noo cluster logs {node}"), "the agent's own log"),
    ]);
    Ok(0)
}

/// The CAPABILITIES cell of `noo cluster status`: the gateway's derived
/// `chat:<model> · embed:<model>`, `-` when it sent none.
pub(crate) fn capabilities_cell(n: &serde_json::Value) -> String {
    match n["capabilities_summary"].as_str().filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => ui::muted("-").to_string(),
    }
}

/// The per-role block of `noo cluster show`: one line per role placement with
/// its model, backend, present/missing and the resident size when the node
/// measured one. Pure (returns the text) so it is tested without a gateway.
#[cfg(test)]
pub(crate) fn role_capabilities_section(n: &serde_json::Value) -> String {
    role_capabilities_section_with(n, None)
}

/// The `place` line for the llama.cpp container's derived memory limit (the
/// gateway's `memory_limit`), if it chose one.
pub(crate) fn memory_limit_line(resp: &serde_json::Value) -> Option<String> {
    let m = resp["memory_limit"].as_object()?;
    let gb = m.get("bytes")?.as_u64()? as f64 / 1e9;
    let why = m.get("why").and_then(|w| w.as_str()).unwrap_or("");
    Some(format!("memory limit {gb:.1} GB  {}", ui::muted(why)))
}

/// The `mem` cell of `noo cluster desired`: a llama.cpp placement's derived
/// container memory limit, or `-` (the agent's own default).
pub(crate) fn mem_cell(p: &serde_json::Value) -> String {
    match p["memory_limit_bytes"].as_u64() {
        Some(b) => format!("{:.1} GB", b as f64 / 1e9),
        None => ui::muted("-").to_string(),
    }
}

/// The `on` cell: the placement's declared hardware target, or what it falls
/// back to when undeclared.
pub(crate) fn target_cell(p: &serde_json::Value) -> String {
    match p["target"].as_str() {
        Some(t) => t.to_string(),
        None if p["env"]["N_GPU_LAYERS"].as_str() == Some("0") => format!("cpu {}", ui::muted("(N_GPU_LAYERS=0)")),
        None => ui::muted("-").to_string(),
    }
}

/// The usage profile row: the effective profile and whether it was set or is
/// the default.
pub(crate) fn usage_cell(node_cfg: &serde_json::Value) -> String {
    match (node_cfg["usage_profile_effective"].as_str(), node_cfg["usage_profile_source"].as_str()) {
        (Some(u), Some(src)) => format!("{u} {}", ui::muted(&format!("({src}; `noo cluster set-config <node> --usage shared|dedicated`)"))),
        _ => match node_cfg["usage_profile"].as_str() {
            Some(u) => u.to_string(),
            None => ui::muted("not reported (an older gateway)").to_string(),
        },
    }
}

/// [`role_capabilities_section`] with each role's hardware target from the
/// desired placements (`placements`, when read).
pub(crate) fn role_capabilities_section_with(n: &serde_json::Value, placements: Option<&serde_json::Value>) -> String {
    let mut out = format!("{}\n", ui::section("Roles"));
    let caps = n["role_capabilities"].as_array();
    let Some(caps) = caps.filter(|c| !c.is_empty()) else {
        out.push_str(&format!("  {}\n", ui::muted("no role placements (or an older gateway that does not derive them)")));
        return out;
    };
    for c in caps {
        let state = c["state"].as_str().unwrap_or("?");
        let cell = match state {
            "live" => "present".to_string(),
            "unknown" => ui::muted("present? (the agent does not report model presence)").to_string(),
            "missing" => ui::warn("missing").to_string(),
            "down" => ui::warn("backend not running").to_string(),
            "stopped" => ui::muted("stopped").to_string(),
            other => other.to_string(),
        };
        let size = match c["resident_bytes"].as_u64() {
            Some(b) => format!("  resident {:.1} GB (measured)", b as f64 / 1e9),
            None => String::new(),
        };
        let on = placements
            .and_then(|ps| ps.as_array())
            .and_then(|ps| ps.iter().find(|p| p["backend"] == c["backend"] && p["role"].as_str().filter(|r| !r.is_empty()).unwrap_or("chat") == c["role"].as_str().unwrap_or("chat")))
            .map(|p| format!(" ({})", target_cell(p)))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {:<8} {} on {}{}  {}{}\n",
            c["role"].as_str().unwrap_or("?"),
            c["model"].as_str().unwrap_or("?"),
            c["backend"].as_str().unwrap_or("?"),
            on,
            cell,
            size
        ));
    }
    out
}

pub fn cluster_desired(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [node] = args else { return Err(Unhandled) };
    if node.starts_with('-') {
        return Err(Unhandled);
    }
    let body = get_json(
        g,
        &format!("/api/cluster/nodes/{}/desired-config", super::urlencode(node)),
        true,
        10,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let n = &body["node"];
    let dash = ui::dash();
    println!("{}", ui::header(node, Some("desired state")));
    if n.is_null() {
        println!("{}", ui::muted("no config row"));
        ui::guide(&[
            (&format!("noo cluster set-config {node} --data-root <path>"), "creates the row; other keys: --gpu-limit, --backends"),
            (&format!("noo cluster place {node} <backend> <model>"), "adds a placement once the row exists"),
        ]);
    } else {
        let mut rows: Vec<(&str, String)> = vec![
            ("ip", n["ip_address"].as_str().unwrap_or(dash).to_string()),
            ("tier", n["tier"].as_i64().map(|t| t.to_string()).unwrap_or_else(|| dash.into())),
            ("ssh user", n["ssh_user"].as_str().unwrap_or(dash).to_string()),
            ("data root", n["data_root"].as_str().unwrap_or(dash).to_string()),
            ("models dir", n["models_dir"].as_str().unwrap_or(dash).to_string()),
        ];
        if !n["gpu_model"].is_null() || !n["vram_gb"].is_null() {
            let complete = !n["gpu_model"].is_null() && !n["vram_gb"].is_null();
            rows.push((
                "gpu override",
                format!(
                    "{} ({} GB){}",
                    n["gpu_model"].as_str().unwrap_or(dash),
                    n["vram_gb"].as_f64().map(|v| v.to_string()).unwrap_or_else(|| dash.into()),
                    if complete { String::new() } else { format!("  {}", ui::warn("inactive — needs BOTH gpu-model and vram-gb")) },
                ),
            ));
        }
        rows.push((
            "loop budget",
            match n["default_loop_budget"].as_i64() {
                Some(b) => format!("{b} loops per task (this node's default)"),
                None => "cluster default (NOO_TASK_LOOP_BUDGET, else 20)".to_string(),
            },
        ));
        rows.push(("usage", usage_cell(n)));
        rows.push((
            "harness",
            match n["harness_policy"].as_str().unwrap_or("manual") {
                "auto" => "auto — follows this node's chat backend".to_string(),
                "off" => "off — never runs the loop here".to_string(),
                _ => "manual — only an explicit `cluster place <node> harness`".to_string(),
            },
        ));
        let pol = &n["companion_policy"];
        rows.push((
            "companion policy",
            if pol.is_null() {
                "gateway default (battery ≥ 25%, wifi/ethernet, not serious/critical)".to_string()
            } else {
                let mut parts = Vec::new();
                if let Some(p) = pol["min_battery_pct"].as_f64() { parts.push(format!("battery ≥ {p}%")); }
                if let Some(w) = pol["require_wifi"].as_bool() { parts.push(if w { "wifi/ethernet only".into() } else { "any network".into() }); }
                if let Some(a) = pol["blocked_thermal_states"].as_array() {
                    let s: Vec<&str> = a.iter().filter_map(|x| x.as_str()).collect();
                    parts.push(format!("not {}", s.join("/")));
                }
                format!("{} (own; unset keys follow the default)", parts.join(", "))
            },
        ));
        print!("{}", ui::kv(&rows));
    }
    let empty = Vec::new();
    let placements = body["placements"].as_array().unwrap_or(&empty);
    println!("{}", ui::section("placements"));
    if placements.is_empty() {
        println!("{}", ui::muted("no placements"));
        return Ok(0);
    }
    // ACTUAL beside DESIRED. `desired_state: running`
    // was read as "it is running" for half an hour while a harness failed
    // to start every five minutes, because the node's own report was on a
    // different screen. A second call rather than widening
    // /desired-config, which node-agents poll on every reconcile and which
    // is their contract, not ours.
    // AUTHENTICATED. This shipped with `false`, so the call sent no
    // credential and the gateway answered 401 — which the CLI then
    // rendered as "the stored credential is expired or revoked — run
    // `noo auth login` again". The operator ran it twice, with a fresh
    // read/write/admin token, and saw the same line both times, because
    // the credential was never the problem: none was sent.
    //
    // It also truncated the command: this call sits AFTER the
    // empty-placements early return, so a node WITH placements never got
    // its table, and a reader could reasonably conclude the node had
    // none. That happened on host3 (2026-09-21) and nearly cost a
    // needless re-placement of its vLLM backend.
    let live = get_json(g, "/api/cluster/nodes", true, 10);
    let node_live = live["nodes"]
        .as_array()
        .and_then(|ns| ns.iter().find(|n| n["id"].as_str() == Some(node.as_str())))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let rows: Vec<Vec<String>> = placements
        .iter()
        .map(|p| {
            let backend = p["backend"].as_str().unwrap_or("?");
            let role = p["role"].as_str().filter(|r| !r.is_empty()).unwrap_or("chat");
            // The role's own state when the gateway derived one (a second
            // role on the same backend must not read as the first's).
            let role_state = node_live["role_capabilities"].as_array().and_then(|cs| {
                cs.iter().find(|c| c["backend"] == backend && c["role"] == role).and_then(|c| c["state"].as_str())
            });
            vec![
                truncate(backend, 12),
                role.to_string(),
                truncate(p["model"].as_str().unwrap_or(""), 52),
                target_cell(p),
                mem_cell(p),
                p["port"].as_i64().map(|v| v.to_string()).unwrap_or_default(),
                if p["tls"].as_bool().unwrap_or(false) { "tls".into() } else { String::new() },
                ui::state(p["desired_state"].as_str().unwrap_or("?")),
                match role_state {
                    Some("missing") => ui::warn("model missing").to_string(),
                    Some("down") => ui::warn("not running").to_string(),
                    _ => actual_cell(&node_live, backend, dash),
                },
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left("backend"),
                Col::left("role"),
                Col::left("model"),
                Col::left("on"),
                Col::right("mem"),
                Col::right("port"),
                Col::left("tls"),
                Col::left("desired"),
                Col::left("actual"),
            ],
            &rows,
        )
    );
    if let Some(r) = refusal_for(&node_live, "harness") {
        println!();
        ui::warned(&format!("harness: {r}"));
    }
    // Why a model is missing, with the command that fixes it.
    for p in placements {
        let backend = p["backend"].as_str().unwrap_or("?");
        if backend_model_missing(&node_live, backend) {
            if let Some(r) = refusal_for(&node_live, backend) {
                println!();
                ui::warned(&format!("{backend}: {r}"));
            }
        }
    }
    Ok(0)
}

/// Parsed `noo cluster proposals` surface.
#[derive(Debug, PartialEq)]
struct ProposalsArgs {
    status: Option<String>,
    limit: Option<u64>,
}

fn parse_proposals_args(args: &[String]) -> Result<ProposalsArgs, Unhandled> {
    let mut out = ProposalsArgs { status: None, limit: None };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--status" => out.status = Some(it.next().ok_or(Unhandled)?.clone()),
            "--limit" | "-n" => {
                out.limit = Some(it.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?)
            }
            _ => return Err(Unhandled),
        }
    }
    Ok(out)
}

/// `noo cluster proposals [--status <s>] [--limit <n>]` — POST
/// /api/cluster/proposals.
///
/// The enrolment proposals agents file, with the host IN FULL. A channel
/// notice masks a tailnet host (the egress floor), so before this the only
/// way to see which machine was asking was the dashboard; the notice now
/// names this command as its next step.
pub fn cluster_proposals(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let a = parse_proposals_args(args)?;
    let mut req = serde_json::json!({});
    if let Some(s) = &a.status {
        req["status"] = s.as_str().into();
    }
    if let Some(n) = a.limit {
        req["limit"] = n.into();
    }
    let body = post_json(g, "/api/cluster/proposals", &req, true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let proposals = body["proposals"].as_array().unwrap_or(&empty);
    let dash = ui::dash();
    let s = |v: &serde_json::Value| v.as_str().filter(|x| !x.is_empty()).unwrap_or(dash).to_string();
    if proposals.is_empty() {
        let scope = a.status.as_deref().map(|s| format!(" {s}")).unwrap_or_default();
        println!("{}", ui::muted(&format!("no{scope} enrolment proposals")));
        return Ok(0);
    }
    println!("{}", ui::header("enrolment proposals", Some(&format!("{} shown", proposals.len()))));
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut any_pending = false;
    for p in proposals {
        let status = s(&p["status"]);
        any_pending |= status == "pending";
        rows.push(vec![
            s(&p["id"]),
            ui::state(&status),
            s(&p["host"]),
            s(&p["user_name"]),
            s(&p["role"]),
            truncate(&s(&p["reason"]), 40),
            s(&p["created_at"]),
        ]);
    }
    print!(
        "{}",
        ui::table(
            &[Col::left("id"), Col::left("status"), Col::left("host"), Col::left("user"), Col::left("role"), Col::left("reason"), Col::left("filed")],
            &rows,
        )
    );
    if any_pending {
        println!(
            "{}",
            ui::muted("decide a pending one from the dashboard's proposals page or the chat card's buttons")
        );
    }
    Ok(0)
}

/// What the NODE says about `backend`, for the ACTUAL column.
///
/// A dash means the node has not said — never "stopped". A node that has
/// not reported is not a node reporting absence, and rendering the two the
/// same is the mistake this column exists to end (CLI_STYLE_GUIDE §4,
/// "Absence is never a negative").
fn actual_cell(node_live: &serde_json::Value, backend: &str, dash: &str) -> String {
    if node_live.is_null() {
        return ui::muted(dash);
    }
    // Host services (the harness) report a real state; containers are
    // reported by presence in running_backends.
    if let Some(st) = node_live["host_services"][backend]["state"].as_str() {
        return match st {
            "running" => ui::state("running"),
            "" => ui::muted(dash),
            other => ui::state(other),
        };
    }
    match node_live["running_backends"].as_object() {
        // The container runs but its model server does not hold the placed
        // model: requests to it 404, so it is not "running".
        // Only a node that REPORTS the absence reads this way; an older agent
        // that sends no `model_presence` keeps the container-level reading.
        Some(rb) if rb.contains_key(backend) && backend_model_missing(node_live, backend) => {
            ui::warn("model missing")
        }
        Some(rb) if rb.contains_key(backend) => ui::state("running"),
        // The node reported its backends and this one was not among them.
        Some(_) => ui::state("not running"),
        None => ui::muted(dash),
    }
}

/// True only when the node REPORTS that `backend`'s model is absent from its
/// model server (`model_presence.<backend>.present == false`).
/// No field, no entry or a non-boolean is "not said", never "missing".
fn backend_model_missing(node: &serde_json::Value, backend: &str) -> bool {
    node["model_presence"][backend]["present"].as_bool() == Some(false)
}

/// The node's standing refusal for `target`, if any — the REASON a thing
/// is not running, which is the half an ACTUAL column cannot carry.
fn refusal_for(node_live: &serde_json::Value, target: &str) -> Option<String> {
    node_live["reconcile_refusals"].as_array()?.iter().find_map(|r| {
        (r["target"].as_str() == Some(target)).then(|| r["reason"].as_str().unwrap_or("refused").to_string())
    })
}

/// The harness column of `noo cluster status`: what the node REPORTS its
/// harness is doing, from `host_services`.
///
/// A dash means the node has not said — an older agent, or one that has
/// not reported since it started. It is never rendered as "stopped":
/// absence is not a negative (CLI_STYLE_GUIDE §4). "absent" is the node
/// itself saying the unit is not installed, which is a real answer.
fn harness_cell(n: &serde_json::Value) -> String {
    match n["host_services"]["harness"]["state"].as_str() {
        None | Some("") => ui::muted(ui::dash()),
        Some("running") => ui::state("running"),
        Some("stopped") => ui::warn("stopped"),
        Some("absent") => ui::muted("absent"),
        Some(other) => ui::state(other),
    }
}

/// `noo cluster place NODE BACKEND MODEL [--on cpu|gpu] [--env KEY=VALUE]... [--port P] [--tls]
/// [--image IMG] [--stopped]` — PUT /api/cluster/nodes/{node}/placements/{backend}.
/// Declares that NODE should run BACKEND with MODEL; the node-agent
/// converges within 5 min.
///
/// `--on` declares the hardware (stored with the placement); the runtime
/// tuning keys (threads, context, batch, parallel slots) are then chosen from
/// the node's reported hardware and usage profile unless `--env` names them
/// (`cluster_tune`).
pub fn cluster_place(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positional: Vec<String> = Vec::new();
    let mut port: Option<i64> = None;
    let mut tls = false;
    let mut image: Option<String> = None;
    let mut stopped = false;
    let mut force = false;
    let mut role: Option<String> = None;
    let mut kind: Option<String> = None;
    let mut env_changes: Vec<(String, Option<String>)> = Vec::new();
    let mut on: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            // The hardware target: cpu | gpu. Stored with the placement.
            "--on" => on = Some(iter.next().ok_or(Unhandled)?.clone()),
            // Place even when `noo cluster fit` says the models do not fit
            // the node's memory (the gateway otherwise refuses with a 409).
            "--force" => force = true,
            // Placement env (repeatable): runtime tuning the node's agent
            // applies to the backend, e.g. VLLM_TOOL_PARSER=gemma4. Merged
            // into what the placement already carries; `KEY=` removes KEY.
            // Before this flag the only way to set one was a hand-built curl
            // with a token read out of the credential file (2026-09-29).
            "--env" => env_changes.push(parse_env_change(iter.next().ok_or(Unhandled)?).ok_or(Unhandled)?),
            "--port" => port = Some(iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?),
            "--tls" => tls = true,
            "--image" => image = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--stopped" => stopped = true,
            // What the backend serves. `embed` is what makes the node's agent
            // advertise the `embed` capability and route /embed to this
            // backend; a chat placement of an embedding model is invisible
            // to the mesh embedder (host2 + harrier, 2026-09-09).
            "--role" => role = Some(iter.next().ok_or(Unhandled)?.clone()),
            // Which harness runs on the node: `noo` (the
            // default) or a kind from config/harness-kinds.json. Only meaningful with the
            // `harness` backend; travels in the placement's env.
            "--kind" => kind = Some(iter.next().ok_or(Unhandled)?.clone()),
            t if t.starts_with('-') => return Err(Unhandled),
            t => positional.push(t.to_string()),
        }
    }
    let [node, backend, model] = positional.as_slice() else { return Err(Unhandled) };
    if let Some(k) = &kind {
        if backend != "harness" {
            crate::output::fail(g.json, crate::output::ExitCode::Usage, "bad_kind",
                "--kind belongs to the `harness` backend only", None);
        }
        let kinds = harness_kind_names();
        if !kinds.iter().any(|n| n == k) {
            crate::output::fail(g.json, crate::output::ExitCode::Usage, "bad_kind",
                &format!("--kind must be one of {}", kinds.join(", ")), None);
        }
    }
    // The harness is placed like a backend but serves the
    // LOOP, not a model: its "model" is the chat model on that node it
    // should point at, or `auto` for whichever chat placement the node has.
    // Its role is implied — `--role` on it is a mistake, not a choice.
    if backend == "harness" {
        match role.as_deref() {
            None | Some("harness") => role = Some("harness".to_string()),
            Some(_) => crate::output::fail(g.json, crate::output::ExitCode::Usage, "bad_role",
                "the harness has no --role: `noo cluster place <node> harness <model|auto>`", None),
        }
    }
    if let Some(r) = &role {
        if !matches!(r.as_str(), "chat" | "embed" | "rerank" | "harness") {
            crate::output::fail(g.json, crate::output::ExitCode::Usage, "bad_role",
                "--role must be chat, embed or rerank", None);
        }
        if r == "harness" && backend != "harness" {
            crate::output::fail(g.json, crate::output::ExitCode::Usage, "bad_role",
                "--role harness belongs to the `harness` backend only", None);
        }
    }
    if on.is_some() && backend == "harness" {
        crate::output::fail(g.json, crate::output::ExitCode::Usage, "bad_target",
            "the harness is a host service: --on belongs to model backends", None);
    }
    // The desired state, read once: the role guard, the env merge and the
    // tuning all start from it. get_json fails the command when the read
    // fails: merging onto nothing would silently drop the stored env.
    let desired = if backend != "harness" || !env_changes.is_empty() || kind.is_some() {
        get_json(g, &format!("/api/cluster/nodes/{}/desired-config", super::urlencode(node)), true, 10)
    } else {
        serde_json::Value::Null
    };
    // A bare `place` means the chat role (#837). If this node already runs
    // THIS model on THIS backend under another role, re-placing it without
    // --role would add a CHAT row serving that model (an embedder answering
    // chat). The operator meant the existing role: refuse and name it.
    if role.is_none() && backend != "harness" {
        if let Some(r) = other_role_for_same_model(&desired["placements"], backend, model) {
            let fix = format!("noo cluster place {node} {backend} {model} --role {r}");
            crate::output::fail(g.json, crate::output::ExitCode::Usage, "role_required",
                &format!("{node} already runs {model} on {backend} as role {r}; without --role this would add a chat placement for it"),
                Some(&fix));
        }
    }
    let mut body = serde_json::json!({
        "model": model,
        "desired_state": if stopped { "stopped" } else { "running" },
        "tls": tls,
    });
    if let Some(r) = &role {
        body["role"] = serde_json::json!(r);
    }
    if force {
        body["force"] = serde_json::json!(true);
    }
    if let Some(p) = port {
        body["port"] = serde_json::json!(p);
    }
    if let Some(img) = &image {
        body["image"] = serde_json::json!(img);
    }
    if let Some(k) = &kind {
        env_changes.push(("NOO_HARNESS_KIND".to_string(), Some(k.clone())));
    }
    // The controller REPLACES a placement's env with whatever is sent, so
    // merge onto the stored one here.
    let current = current_env_for(&desired["placements"], backend, role.as_deref(), model);
    let mut placed_on: Option<PlacedOn> = None;
    if backend != "harness" {
        let p = plan_target_and_tuning(g, node, backend, model, role.as_deref(), on.as_deref(), &desired, &current, &env_changes);
        env_changes.extend(p.env_changes.iter().cloned());
        body["target"] = serde_json::json!(p.target);
        if let Some(b) = p.size_bytes {
            body["model_size_bytes"] = serde_json::json!(b);
        }
        placed_on = Some(p);
    }
    if !env_changes.is_empty() {
        body["env"] = merge_placement_env(&current, &env_changes);
    }
    let place_path = format!("/api/cluster/nodes/{}/placements/{}", super::urlencode(node), super::urlencode(backend));
    // The gateway refuses a placement whose image is not staged on the
    // artifact rail (nodes pull only from there). This CLI runs on the
    // controller with its registry login, so it stages the image and places
    // again — the operator gets the placement, not a homework assignment.
    let resp = match crate::http::put_json_try(g, &place_path, &body, true, 10) {
        Ok(v) => v,
        Err(e) => {
            if let Some((img, arch)) = crate::commands::image_stage::parse_not_staged(&e) {
                if !g.json {
                    ui::step(&format!("{img} is not staged for {arch} — staging it on the artifact rail first"));
                }
                if let Err(se) = crate::commands::image_stage::stage_and_record(g, &img, &arch, "place") {
                    crate::output::fail(g.json, crate::output::ExitCode::Generic, "image_not_staged",
                        &format!("could not stage {img} for {arch}: {se}"),
                        Some(&format!("noo cluster stage-images -i {img} --arch {arch}")));
                }
            }
            // Placed again after staging, or the refusal surfaces through the
            // standard error path (exit code and all).
            put_json(g, &place_path, &body, true, 10)
        }
    };
    if g.json {
        let mut resp = resp;
        if let Some(p) = &placed_on {
            resp["placed_on"] = p.to_json();
        }
        println!("{resp}");
        return Ok(0);
    }
    if let Some(p) = &placed_on {
        print!("{}", p.render());
    }
    if let Some(line) = memory_limit_line(&resp) {
        println!("  {line}");
    }
    // The fit check's warnings (tight, forced, unestimated) are part of the
    // answer, not noise: a placement that squeezes the node should say so.
    if let Some(ws) = resp["warnings"].as_array() {
        for w in ws.iter().filter_map(|w| w.as_str()) {
            println!("{}", ui::status_line(Glyph::Warn, w));
        }
    }
    // "agent reconciles within 5 min" is FALSE for a backend the agent does
    // not manage. A native backend (a Metal ollama on a Mac, say) is one the
    // agent found, not one it starts: the reconciler skips it with a log
    // line, so this placement is recorded and never converges.
    //
    // Saying so HERE is the point. The information existed — the agent
    // returns 501 backend_runtime_unmanaged if you try to start it, and the
    // reconciler logs the skip — but only to someone who already suspected
    // something was wrong. A placement that will not happen should say so at
    // the moment it is made, not to whoever goes looking later.
    let native = fetch_node_opt(g, node)
        .map(|n| n["backend_runtimes"][backend].as_str() == Some("native"))
        .unwrap_or(false);
    if native {
        ui::done(&format!("{node}: {backend} → {model} recorded"));
        println!("{}", ui::status_line(Glyph::Warn, &format!(
            "{node} serves {backend} NATIVELY — this agent reports it but does not \
             start, stop or converge it, so this placement will not be applied")));
        ui::guide(&[
            (&format!("noo cluster show {node}"), "shows which runtime serves each backend"),
            ("(on the node)", "start or change the model there — the agent will report it"),
        ]);
        return Ok(0);
    }
    ui::done(&format!(
        "{node}: {backend} → {model} ({}) — agent reconciles within 5 min",
        ui::state(if stopped { "stopped" } else { "running" })
    ));
    Ok(0)
}

/// What `place` decided about the hardware: the target, why, and each tuned key.
pub(crate) struct PlacedOn {
    target: &'static str,
    target_why: String,
    usage: String,
    usage_source: String,
    applied: Vec<super::cluster_tune::Applied>,
    /// The env changes the target and the tuning add (explicit `--env` is not here).
    env_changes: Vec<(String, Option<String>)>,
    size_bytes: Option<u64>,
    notes: Vec<String>,
}

impl PlacedOn {
    fn to_json(&self) -> serde_json::Value {
        use super::cluster_tune::Applied;
        serde_json::json!({
            "target": self.target,
            "target_why": self.target_why,
            "usage_profile": self.usage,
            "usage_profile_source": self.usage_source,
            "model_size_bytes": self.size_bytes,
            "tuning": self.applied.iter().map(|a| match a {
                Applied::Set(c) => serde_json::json!({"key": c.key, "value": c.value, "why": c.why, "how": "tuned"}),
                Applied::Explicit(k) => serde_json::json!({"key": k, "how": "explicit --env"}),
                Applied::Kept(k, v) => serde_json::json!({"key": k, "value": v, "how": "kept"}),
            }).collect::<Vec<_>>(),
            "notes": self.notes,
        })
    }

    /// The lines `place` prints: what it chose and why.
    pub(crate) fn render(&self) -> String {
        use super::cluster_tune::Applied;
        let mut out = format!(
            "{}\n",
            ui::status_line(Glyph::Step, &format!("on {} — {}; {} node ({})", self.target, self.target_why, self.usage, self.usage_source))
        );
        for a in &self.applied {
            let line = match a {
                Applied::Set(c) => format!("{}={}  {}", c.key, c.value, ui::muted(&c.why)),
                Applied::Explicit(k) => format!("{k} {}", ui::muted("from --env (yours wins)")),
                Applied::Kept(k, v) => format!("{k}={v} {}", ui::muted("kept (already on this placement)")),
            };
            out.push_str(&format!("  {line}\n"));
        }
        for n in &self.notes {
            out.push_str(&format!("  {}\n", ui::muted(n)));
        }
        out
    }
}

/// Resolve `--on` and tune the runtime keys for a placement (`cluster_tune`).
/// Fails the command on an impossible target (vllm on cpu, gpu on a node with
/// none); every other gap (an older gateway, an unreported node) degrades to
/// fewer tuned keys with a note, never to a refusal.
#[allow(clippy::too_many_arguments)]
fn plan_target_and_tuning(
    g: &Globals,
    node: &str,
    backend: &str,
    model: &str,
    role: Option<&str>,
    on: Option<&str>,
    desired: &serde_json::Value,
    current: &serde_json::Value,
    explicit: &[(String, Option<String>)],
) -> PlacedOn {
    use super::cluster_tune as t;
    let role_eff = role.unwrap_or("chat");
    let stored_target = desired["placements"].as_array().and_then(|ps| {
        ps.iter().find(|p| {
            p["backend"].as_str() == Some(backend)
                && p["role"].as_str().filter(|r| !r.is_empty()).unwrap_or("chat") == role_eff
                && p["model"].as_str() == Some(model)
        })
    }).and_then(|p| p["target"].as_str()).map(str::to_string);
    let node_rec = fetch_node_opt(g, node);
    let hw = node_rec.as_ref().map(t::Hardware::of).unwrap_or_default();
    let pre_env = merge_placement_env(current, explicit);
    let target = t::resolve_target(on, backend, &hw, stored_target.as_deref(), &pre_env)
        .unwrap_or_else(|e| fail(g.json, ExitCode::Usage, "bad_target", &e, Some(&format!("noo cluster show {node}"))));
    let target_why = match (on, stored_target.as_deref()) {
        (Some(_), _) => "--on".to_string(),
        (None, Some(s)) if s == target => "as already placed".to_string(),
        _ if t::target_env(backend, "gpu", &pre_env).iter().any(|(k, _)| k == "N_GPU_LAYERS") && target == "cpu" => "N_GPU_LAYERS=0 pins it to cpu".to_string(),
        _ => match hw.has_gpu() {
            Some(true) => "the node has a GPU".to_string(),
            Some(false) => "the node has no GPU".to_string(),
            None => "the node reports no hardware yet: assumed gpu".to_string(),
        },
    };
    let mut env_changes: Vec<(String, Option<String>)> = t::target_env(backend, target, &pre_env)
        .into_iter()
        .filter(|(k, _)| !explicit.iter().any(|(e, _)| e == k))
        .collect();
    let usage = desired["node"]["usage_profile_effective"].as_str().unwrap_or("dedicated").to_string();
    let usage_source = desired["node"]["usage_profile_source"].as_str().unwrap_or("an older gateway: assumed").to_string();
    let size_bytes = t::store_size_bytes(&t::model_store(), model);
    let mut notes = Vec::new();
    // Size the KV from the fit the gateway would judge (read-only).
    let mut fit_env = merge_placement_env(current, explicit);
    fit_env = merge_placement_env(&fit_env, &env_changes);
    let fit = post_json_try(
        g,
        &format!("/api/cluster/nodes/{}/fit", super::urlencode(node)),
        &serde_json::json!({"with": {"backend": backend, "model": model, "role": role, "env": fit_env, "target": target, "model_size_bytes": size_bytes}}),
        true,
        10,
    );
    let (weights_gb, free_gb) = match &fit {
        Ok(f) => (t::weights_in(f, backend, role_eff), t::free_for_kv(f, backend, role_eff, target)),
        Err(e) => {
            notes.push(format!("fit unavailable ({e}): context left at the default"));
            (None, None)
        }
    };
    if hw.cpu_cores.is_none() && target == "cpu" && backend == "llamacpp" {
        notes.push("the node reports no cpu_cores: threads left at the backend default".into());
    }
    if backend == "ollama" && target == "cpu" {
        notes.push("ollama on cpu: the agent gives the container no GPU device".into());
    }
    let choices = t::tune(&t::TuneInput {
        backend,
        role: role_eff,
        target,
        usage: &usage,
        cpu_cores: hw.cpu_cores,
        weights_gb,
        free_gb,
    });
    let retune = stored_target.as_deref().is_some_and(|s| s != target);
    let applied = t::apply_choices(choices, explicit, current, retune);
    for a in &applied {
        if let t::Applied::Set(c) = a {
            env_changes.push((c.key.to_string(), Some(c.value.clone())));
        }
    }
    PlacedOn { target, target_why, usage, usage_source, applied, env_changes, size_bytes, notes }
}

/// The env a `place` should merge its `--env` changes onto: the stored env of
/// the SAME (backend, role) placement, and only when the model is unchanged.
/// A different role is a different placement, and a new model starts clean -
/// re-placing gemma over harrier inherited harrier's OLLAMA_NUM_PARALLEL=4
/// (2026-10-08). The gateway applies the same rule to an omitted env.
/// The non-chat role under which `placements` already hold `model` on
/// `backend`, if any (a bare `place` of it would add a chat row instead).
pub(crate) fn other_role_for_same_model(
    placements: &serde_json::Value,
    backend: &str,
    model: &str,
) -> Option<String> {
    placements.as_array()?.iter().find_map(|p| {
        let r = p["role"].as_str().filter(|r| !r.is_empty()).unwrap_or("chat");
        (p["backend"].as_str() == Some(backend) && p["model"].as_str() == Some(model) && r != "chat")
            .then(|| r.to_string())
    })
}

pub(crate) fn current_env_for(
    placements: &serde_json::Value,
    backend: &str,
    role: Option<&str>,
    model: &str,
) -> serde_json::Value {
    let want_role = role.unwrap_or(if backend == "harness" { "harness" } else { "chat" });
    placements
        .as_array()
        .and_then(|ps| {
            ps.iter().find(|p| {
                p["backend"].as_str() == Some(backend)
                    && p["role"].as_str().filter(|r| !r.is_empty()).unwrap_or("chat") == want_role
            })
        })
        .filter(|p| p["model"].as_str() == Some(model))
        .map(|p| p["env"].clone())
        .unwrap_or(serde_json::Value::Null)
}

/// `fetch_node` without the exit-on-miss. Used where a node's absence is not
/// worth failing over — an advisory lookup after the real work succeeded.
pub(crate) fn fetch_node_opt(g: &Globals, node_id: &str) -> Option<serde_json::Value> {
    let body = get_json(g, "/api/cluster/nodes", true, 10);
    body["nodes"].as_array()?.iter().find(|n| {
        n["id"].as_str() == Some(node_id) || n["hostname"].as_str() == Some(node_id)
    }).cloned()
}

/// Parse one `--env KEY=VALUE`. An empty VALUE means "remove KEY". Keys are
/// environment-variable names: letters, digits and `_`, not starting with a
/// digit — anything else is a typo the node would refuse anyway.
fn parse_env_change(arg: &str) -> Option<(String, Option<String>)> {
    let (key, value) = arg.split_once('=')?;
    let key = key.trim();
    let valid = !key.is_empty()
        && !key.starts_with(|c: char| c.is_ascii_digit())
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return None;
    }
    Some((key.to_string(), (!value.is_empty()).then(|| value.to_string())))
}

/// Apply env changes onto a placement's stored env (an object, or null for
/// none). Later changes win; a `None` value removes the key.
fn merge_placement_env(current: &serde_json::Value, changes: &[(String, Option<String>)]) -> serde_json::Value {
    let mut env = current.as_object().cloned().unwrap_or_default();
    for (k, v) in changes {
        match v {
            Some(v) => {
                env.insert(k.clone(), serde_json::json!(v));
            }
            None => {
                env.remove(k);
            }
        }
    }
    serde_json::Value::Object(env)
}

#[cfg(test)]
mod placement_env_tests {
    /// A bare re-place of the embedder (live 2026-10-08: `noo cluster place
    /// host9 ollama harrier` after #837) would add a chat row serving an
    /// embedding model. The guard names the existing role; a different model,
    /// or a model only placed as chat, is not refused.
    #[test]
    fn a_bare_place_of_a_model_held_under_another_role_names_that_role() {
        let ps = serde_json::json!([
            {"backend": "ollama", "model": "gemma4:26b-a4b-it-qat", "role": "chat"},
            {"backend": "ollama", "model": "harrier", "role": "embed"},
            {"backend": "llamacpp", "model": "bge-reranker", "role": "rerank"},
        ]);
        assert_eq!(other_role_for_same_model(&ps, "ollama", "harrier").as_deref(), Some("embed"));
        assert_eq!(other_role_for_same_model(&ps, "llamacpp", "bge-reranker").as_deref(), Some("rerank"));
        assert_eq!(other_role_for_same_model(&ps, "ollama", "gemma4:26b-a4b-it-qat"), None, "already chat");
        assert_eq!(other_role_for_same_model(&ps, "ollama", "llama3.2:3b"), None, "a new model is not refused");
        assert_eq!(other_role_for_same_model(&ps, "vllm", "harrier"), None, "another backend is not refused");
        assert_eq!(other_role_for_same_model(&serde_json::json!(null), "ollama", "harrier"), None);
        // an old row with no role is chat
        let legacy = serde_json::json!([{"backend": "ollama", "model": "harrier"}]);
        assert_eq!(other_role_for_same_model(&legacy, "ollama", "harrier"), None);
    }

    use super::{capabilities_cell, current_env_for, merge_placement_env, other_role_for_same_model, parse_env_change, render_fit, role_capabilities_section, role_capabilities_section_with, target_cell, usage_cell, memory_limit_line, mem_cell};
    use serde_json::json;

    #[test]
    fn place_merges_env_only_from_the_same_role_and_model() {
        let placements = json!([
            {"backend": "ollama", "role": "embed", "model": "harrier", "env": {"OLLAMA_NUM_PARALLEL": "4"}},
            {"backend": "ollama", "role": "chat", "model": "gemma", "env": {"A": "1"}}
        ]);
        // The incident: gemma over harrier, no --role -> the chat role, which has its own env.
        assert_eq!(current_env_for(&placements, "ollama", None, "gemma"), json!({"A": "1"}));
        // A new model in the role starts clean.
        assert_eq!(current_env_for(&placements, "ollama", None, "gemma4:new"), serde_json::Value::Null);
        // Embed re-placed with the same model keeps its env; never the chat row's.
        assert_eq!(current_env_for(&placements, "ollama", Some("embed"), "harrier"), json!({"OLLAMA_NUM_PARALLEL": "4"}));
        // A role with no row yet has nothing to inherit.
        assert_eq!(current_env_for(&placements, "ollama", Some("rerank"), "x"), serde_json::Value::Null);
    }

    #[test]
    fn status_and_show_render_the_per_role_capabilities() {
        let n = json!({"capabilities_summary": "chat:gemma4:26b \u{b7} embed:harrier",
            "role_capabilities": [
                {"role": "chat", "backend": "ollama", "model": "gemma4:26b", "state": "live", "resident_bytes": 17_000_000_000u64},
                {"role": "embed", "backend": "ollama", "model": "harrier", "state": "missing", "resident_bytes": null}]});
        assert_eq!(capabilities_cell(&n), "chat:gemma4:26b \u{b7} embed:harrier");
        assert!(!capabilities_cell(&json!({})).is_empty(), "an older gateway renders a placeholder");
        let out = role_capabilities_section(&n);
        assert!(out.contains("gemma4:26b on ollama") && out.contains("present") && out.contains("resident 17.0 GB (measured)"), "{out}");
        assert!(out.contains("harrier on ollama") && out.contains("missing"), "{out}");
    }

    #[test]
    fn fit_screen_shows_the_table_the_verdict_and_the_shortfall() {
        let r = json!({"verdict": "does_not_fit", "total_gb": 18.47, "shortfall_gb": 0.47,
            "budget": {"kind": "unified", "total_gb": 18.0, "headroom_gb": 1.8},
            "warnings": ["w1"],
            "models": [{"model": "harrier", "role": "embed", "weights_gb": 0.4, "kv_gb": 0.0, "overhead_gb": 0.6, "total_gb": 1.0, "source": "estimated"}]});
        let out = render_fit("host6", &r);
        for want in ["harrier", "estimated", "unified", "short by 0.5 GB", "--force", "w1"] {
            assert!(out.contains(want), "missing {want:?} in {out}");
        }
    }

    /// The host8 report: a CPU placement shows its RAM pool, not "6.0 GB vram",
    /// and an unknown size reads "can't judge", not "tight".
    #[test]
    fn fit_screen_shows_each_pool_the_target_and_cant_judge() {
        let r = json!({"verdict": "fits", "total_gb": 18.5, "usage_profile": "shared", "usage_profile_source": "default for a worker",
            "budget": {"kind": "vram", "target": "gpu", "total_gb": 6.0, "headroom_gb": 2.0},
            "budgets": [
                {"kind": "vram", "target": "gpu", "total_gb": 6.0, "headroom_gb": 2.0, "used_gb": 1.0, "verdict": "fits"},
                {"kind": "ram", "target": "cpu", "total_gb": 32.0, "headroom_gb": 3.2, "used_gb": 17.5, "verdict": "fits"}],
            "models": [
                {"model": "harrier", "role": "embed", "target": "gpu", "weights_gb": 0.4, "weights_source": "known", "kv_gb": 0.0, "overhead_gb": 0.6, "total_gb": 1.0, "source": "estimated"},
                {"model": "gemma.gguf", "role": "chat", "target": "cpu", "weights_gb": 15.8, "weights_source": "controller-store", "kv_gb": 1.1, "overhead_gb": 0.6, "total_gb": 17.5, "source": "estimated"}]});
        let out = render_fit("host8", &r).to_lowercase();
        for want in ["budget gpu", "budget cpu", "32.0 gb ram", "17.5 gb used", "controller-store", "shared (default for a worker)", " cpu "] {
            assert!(out.contains(want), "missing {want:?} in {out}");
        }
        let unknown = json!({"verdict": "unknown", "total_gb": 0.6,
            "budgets": [{"kind": "vram", "target": "gpu", "total_gb": 24.0, "headroom_gb": 2.4, "used_gb": 0.6, "verdict": "unknown"}],
            "warnings": ["can't judge Mystery.gguf: no node reports its size"],
            "models": [{"model": "Mystery.gguf", "role": "chat", "target": "gpu", "weights_gb": null, "weights_source": "unknown", "kv_gb": 0.0, "overhead_gb": 0.6, "total_gb": 0.6, "source": "estimated"}]});
        let out = render_fit("host3", &unknown);
        assert!(out.contains("can't judge") && !out.contains("tight"), "{out}");
    }

    #[test]
    fn show_and_desired_render_the_target_and_the_usage_profile() {
        let n = json!({"role_capabilities": [
            {"role": "chat", "backend": "llamacpp", "model": "g.gguf", "state": "live"},
            {"role": "embed", "backend": "ollama", "model": "harrier", "state": "live"}]});
        let ps = json!([
            {"backend": "llamacpp", "role": "chat", "model": "g.gguf", "target": "cpu"},
            {"backend": "ollama", "role": "embed", "model": "harrier", "target": null, "env": {}}]);
        let out = role_capabilities_section_with(&n, Some(&ps));
        assert!(out.contains("g.gguf on llamacpp (cpu)"), "{out}");
        let legacy = json!({"backend": "llamacpp", "target": null, "env": {"N_GPU_LAYERS": "0"}});
        assert!(target_cell(&legacy).starts_with("cpu"));
        let cfg = json!({"usage_profile": null, "usage_profile_effective": "shared", "usage_profile_source": "default for a worker"});
        let u = usage_cell(&cfg);
        assert!(u.contains("shared") && u.contains("default for a worker") && u.contains("--usage"), "{u}");
    }

    #[test]
    fn place_and_desired_show_the_derived_memory_limit() {
        let resp = json!({"memory_limit": {"bytes": 17_500_000_000u64, "why": "model + KV + overhead, 17.5 GB (the fit estimate)"}});
        let line = memory_limit_line(&resp).unwrap();
        assert!(line.contains("memory limit 17.5 GB") && line.contains("fit estimate"), "{line}");
        assert!(memory_limit_line(&json!({"memory_limit": null})).is_none());
        assert_eq!(mem_cell(&json!({"memory_limit_bytes": 16_000_000_000u64})), "16.0 GB");
        assert!(!mem_cell(&json!({})).contains("GB"));
    }

    #[test]
    fn env_args_parse_and_reject_typos() {
        assert_eq!(parse_env_change("VLLM_TOOL_PARSER=gemma4"), Some(("VLLM_TOOL_PARSER".into(), Some("gemma4".into()))));
        assert_eq!(parse_env_change("A=b=c"), Some(("A".into(), Some("b=c".into()))));
        assert_eq!(parse_env_change("VLLM_TOOL_PARSER="), Some(("VLLM_TOOL_PARSER".into(), None)));
        for bad in ["noequals", "=v", "1A=v", "BAD-KEY=v", "SP ACE=v"] {
            assert_eq!(parse_env_change(bad), None, "{bad} should be refused");
        }
    }

    /// The controller replaces env wholesale, so the CLI must carry the keys
    /// it was not asked to touch — host3's parser pair, 2026-09-29.
    #[test]
    fn merge_keeps_untouched_keys_and_removes_on_empty() {
        let current = json!({"VLLM_REASONING_PARSER": "gemma4", "VLLM_TOOL_PARSER": "pythonic"});
        let merged = merge_placement_env(&current, &[("VLLM_TOOL_PARSER".into(), Some("gemma4".into()))]);
        assert_eq!(merged, json!({"VLLM_REASONING_PARSER": "gemma4", "VLLM_TOOL_PARSER": "gemma4"}));

        let removed = merge_placement_env(&merged, &[("VLLM_TOOL_PARSER".into(), None)]);
        assert_eq!(removed, json!({"VLLM_REASONING_PARSER": "gemma4"}));

        let from_none = merge_placement_env(&serde_json::Value::Null, &[("NOO_HARNESS_KIND".into(), Some("noo".into()))]);
        assert_eq!(from_none, json!({"NOO_HARNESS_KIND": "noo"}));
    }
}

/// `noo cluster unplace NODE BACKEND` —
/// DELETE /api/cluster/nodes/{node}/placements/{backend}. The agent stops
/// managing the backend.
///
/// A CONTAINER is left running: it stays visible in `docker ps`, and the
/// operator can see what they left behind. The HARNESS is stopped (#355).
/// The asymmetry is deliberate — the harness is a host service running as
/// a dedicated user with node credentials and a bus subscription, and
/// once the placement is gone nothing reports it and nothing converges
/// it. A container nobody manages is visible; an unmanaged harness is
/// not, which is why one is left and the other is not.
pub fn cluster_unplace(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positional: Vec<&String> = Vec::new();
    let mut role: Option<&String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--role" => role = Some(iter.next().ok_or(Unhandled)?),
            t if t.starts_with('-') => return Err(Unhandled),
            _ => positional.push(tok),
        }
    }
    let [node, backend] = positional.as_slice() else { return Err(Unhandled) };
    let mut path = format!(
        "/api/cluster/nodes/{}/placements/{}",
        super::urlencode(node),
        super::urlencode(backend)
    );
    if let Some(r) = role {
        path.push_str(&format!("?role={}", super::urlencode(r)));
    }
    let resp = delete_json(g, &path, true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    match role {
        Some(r) => ui::done(&format!("{node}: {backend} {r} placement removed")),
        None => ui::done(&format!("{node}: {backend} placement removed")),
    }
    Ok(0)
}

/// `noo cluster fit NODE [--with BACKEND MODEL [--on cpu|gpu] [--role R] [--env K=V]...]` -
/// POST /api/cluster/nodes/{node}/fit. Prints each placement's estimated or
/// measured resident memory against its pool (GPU memory for a gpu
/// placement, RAM for a cpu one) and the verdict (fits / tight / does not fit
/// / can't judge). A GGUF in the controller model store sizes the model.
/// Changes nothing.
pub fn cluster_fit(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut node: Option<&String> = None;
    let mut with: Option<(String, String)> = None;
    let mut role: Option<String> = None;
    let mut on: Option<String> = None;
    let mut env = serde_json::Map::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--on" => {
                let v = iter.next().ok_or(Unhandled)?.clone();
                if !matches!(v.as_str(), "cpu" | "gpu") {
                    fail(g.json, ExitCode::Usage, "bad_target", "--on must be cpu or gpu", None);
                }
                on = Some(v);
            }
            "--with" => {
                let b = iter.next().ok_or(Unhandled)?.clone();
                let m = iter.next().ok_or(Unhandled)?.clone();
                with = Some((b, m));
            }
            "--role" => role = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--env" => {
                let (k, v) = parse_env_change(iter.next().ok_or(Unhandled)?).ok_or(Unhandled)?;
                if let Some(v) = v {
                    env.insert(k, serde_json::json!(v));
                }
            }
            t if t.starts_with('-') => return Err(Unhandled),
            _ if node.is_none() => node = Some(tok),
            _ => return Err(Unhandled),
        }
    }
    let Some(node) = node else { return Err(Unhandled) };
    if with.is_none() && (role.is_some() || !env.is_empty() || on.is_some()) {
        return Err(Unhandled);
    }
    let mut body = serde_json::json!({});
    if let Some((b, m)) = &with {
        if on.as_deref() == Some("cpu") && (b == "vllm" || b == "vllm-secondary") {
            fail(g.json, ExitCode::Usage, "bad_target", "vLLM runs on a GPU only; try llamacpp or ollama with --on cpu", None);
        }
        // With no --on the gateway judges the target the placement would get
        // (declared, else N_GPU_LAYERS=0 means cpu, else the node's GPU).
        let size = super::cluster_tune::store_size_bytes(&super::cluster_tune::model_store(), m);
        body["with"] = serde_json::json!({"backend": b, "model": m, "role": role, "env": env, "target": on, "model_size_bytes": size});
    }
    let resp = post_json(g, &format!("/api/cluster/nodes/{}/fit", super::urlencode(node)), &body, true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    print!("{}", render_fit(node, &resp));
    Ok(if resp["verdict"] == "does_not_fit" { 1 } else { 0 })
}

/// The `noo cluster fit` screen. Pure, so the table and the verdict wording
/// are tested without a gateway.
///
/// One budget line per pool the placements draw on (GPU memory, RAM), each
/// with its own verdict; "can't judge" when a size or the pool is unknown -
/// never dressed up as "tight".
pub(crate) fn render_fit(node: &str, r: &serde_json::Value) -> String {
    let gb = |v: &serde_json::Value| v.as_f64().map(|x| format!("{x:.1}")).unwrap_or_else(|| "-".to_string());
    let verdict_cell = |v: &str| match v {
        "fits" => ui::state("fits").to_string(),
        "tight" => ui::warn("tight").to_string(),
        "does_not_fit" => ui::warn("does not fit").to_string(),
        "unknown" => ui::warn("can't judge").to_string(),
        other => other.to_string(),
    };
    let mut out = format!("{}\n", ui::header(node, Some("memory fit")));
    // Older gateways send one `budget` and no `budgets`.
    let pools: Vec<serde_json::Value> = match r["budgets"].as_array() {
        Some(b) => b.clone(),
        None => r["budget"].as_object().map(|_| vec![r["budget"].clone()]).unwrap_or_default(),
    };
    let usage = r["usage_profile"].as_str().map(|u| match r["usage_profile_source"].as_str() {
        Some(src) => format!("{u} ({src})"),
        None => u.to_string(),
    });
    let mut kv: Vec<(&str, String)> = Vec::new();
    let labels: Vec<String> = pools.iter().map(|b| format!("budget {}", b["target"].as_str().unwrap_or(""))).collect();
    for (b, label) in pools.iter().zip(&labels) {
        let line = if b["total_gb"].is_null() {
            format!("{} {}", ui::warn("can't judge"), ui::muted("the node reports no memory for this pool"))
        } else {
            format!(
                "{} GB {} ({} GB headroom reserved): {} GB used{}",
                gb(&b["total_gb"]),
                b["kind"].as_str().unwrap_or("?"),
                gb(&b["headroom_gb"]),
                gb(&b["used_gb"]),
                b["verdict"].as_str().map(|v| format!(", {}", verdict_cell(v))).unwrap_or_default(),
            )
        };
        kv.push((label.trim_end(), line));
    }
    if let Some(u) = usage {
        kv.push(("usage", u));
    }
    if pools.is_empty() && r["models"].as_array().is_none_or(|m| m.is_empty()) {
        out.push_str(&format!("  {}\n", ui::muted("no running placements hold memory on this node")));
    } else if pools.is_empty() {
        out.push_str(&format!("  {}\n", ui::muted("the node reports no memory: can't judge the fit")));
    }
    if !kv.is_empty() {
        out.push_str(&format!("{}\n", ui::kv(&kv)));
    }
    let rows: Vec<Vec<String>> = r["models"]
        .as_array()
        .map(|ms| {
            ms.iter()
                .map(|m| {
                    vec![
                        m["model"].as_str().unwrap_or("?").to_string(),
                        m["role"].as_str().unwrap_or("?").to_string(),
                        m["target"].as_str().unwrap_or("-").to_string(),
                        gb(&m["weights_gb"]),
                        gb(&m["kv_gb"]),
                        gb(&m["overhead_gb"]),
                        gb(&m["total_gb"]),
                        match (m["source"].as_str(), m["weights_source"].as_str()) {
                            (Some("measured"), _) => "measured".to_string(),
                            (Some(s), Some(w)) if w != "vllm" => format!("{s} ({w})"),
                            (Some(s), _) => s.to_string(),
                            _ => "?".to_string(),
                        },
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    out.push_str(&ui::table(
        &[Col::left("model"), Col::left("role"), Col::left("on"), Col::right("weights GB"), Col::right("kv GB"), Col::right("overhead GB"), Col::right("total GB"), Col::left("source")],
        &rows,
    ));
    let total_of = if pools.len() == 1 { format!(" of {} GB", gb(&pools[0]["total_gb"])) } else { String::new() };
    out.push_str(&format!("total {} GB{}: {}\n", gb(&r["total_gb"]), total_of, verdict_cell(r["verdict"].as_str().unwrap_or("?"))));
    if r["verdict"] == "does_not_fit" {
        out.push_str(&format!("short by {} GB; `noo cluster place` refuses this unless --force\n", gb(&r["shortfall_gb"])));
    }
    if r["verdict"] == "unknown" {
        out.push_str("can't judge: a size or a memory figure is missing (see below); `noo cluster place` does not refuse on that\n");
    }
    if let Some(ws) = r["warnings"].as_array() {
        for w in ws.iter().filter_map(|w| w.as_str()) {
            out.push_str(&format!("  {}\n", ui::muted(w)));
        }
    }
    out
}

// ── SSH commands (exec / logs) ──────────────────────────────────────
//
// Node resolution mirrors the Python `_resolve_node`: look the node up in
// GET /api/cluster/nodes by id or hostname, take ip_address|ip|hostname as
// the SSH host. Invocation mirrors `_ssh_pai` minus the venv wrap (worker
// nodes have no Python noo install; the raw command is what agents want):
//   ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=10 \
//       [user@]ip <command>

/// Look a node up by id or hostname via the gateway; exits if not found.
pub(crate) fn fetch_node(g: &Globals, node_id: &str) -> serde_json::Value {
    let body = get_json(g, "/api/cluster/nodes", true, 10);
    let empty = Vec::new();
    let nodes = body["nodes"].as_array().unwrap_or(&empty);
    for n in nodes {
        if n["id"].as_str() == Some(node_id) || n["hostname"].as_str() == Some(node_id) {
            return n.clone();
        }
    }
    let known: Vec<&str> = nodes.iter().filter_map(|n| n["id"].as_str()).collect();
    fail(
        g.json,
        ExitCode::Generic,
        "node_not_found",
        &format!("Node '{node_id}' not found"),
        Some(&format!("known nodes: {}", known.join(", "))),
    );
}

/// `noo cluster logs [NODE] [SERVICE] [-b BACKEND] [-n TAIL]` — container
/// logs from a node, over the mesh.
///
/// Was `ssh node docker logs …`. The controller's SSH
/// lane is retired and the fleet is pull-only, so that path is dead on arrival: the
/// node-agent already exposes `GET /logs/{container}` and the gateway
/// already proxies it at `/api/logs/node/{node}/{container}`. This uses
/// that rail, which also works on a node the operator has no key for —
/// which is now every node.
pub fn cluster_logs(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positional: Vec<String> = Vec::new();
    let mut backend: Option<String> = None;
    let mut tail: u64 = 50;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-b" | "--backend" => backend = Some(iter.next().ok_or(Unhandled)?.clone()),
            "-n" | "--tail" => {
                tail = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?
            }
            // `-f` streamed because ssh held the pipe open. The rail is a
            // one-shot tail, so rather than fake it with a poll loop, say
            // where streaming lives.
            "-f" | "--follow" => {
                fail(
                    g.json,
                    ExitCode::Usage,
                    "follow_unsupported",
                    "`--follow` is not available over the mesh log rail (it is a one-shot tail)",
                    Some("no live follow yet — poll the log store instead: `noo logs query <logql>`"),
                );
            }
            // `-u` chose the SSH user. There is no SSH user any more.
            "-u" | "--user" => {
                fail(
                    g.json,
                    ExitCode::Usage,
                    "user_unsupported",
                    "`--user` selected an SSH account; cluster logs no longer uses SSH",
                    Some("drop the flag — the node-agent serves these logs over the mesh"),
                );
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => positional.push(t.to_string()),
        }
    }
    let (node, service) = match positional.as_slice() {
        [] => (None, None),
        [node] => (Some(node.clone()), None),
        [node, service] => (Some(node.clone()), Some(service.clone())),
        _ => return Err(Unhandled),
    };
    let backend = backend.or(service);
    let container = match &backend {
        Some(b) if b.starts_with("noo-") => b.clone(),
        Some(b) => format!("noo-{b}"),
        None => "noo-node-agent".to_string(),
    };

    let tail = tail.min(2000);
    if let Some(node) = node {
        let n = fetch_node(g, &node);
        let id = n["id"].as_str().unwrap_or(node.as_str()).to_string();
        if !g.json {
            println!("{}", ui::section(&format!("{id} ({container})")));
        }
        return Ok(print_node_logs(g, &id, &container, tail));
    }

    let body = get_json(g, "/api/cluster/nodes", true, 10);
    let empty = Vec::new();
    let nodes: Vec<&serde_json::Value> = body["nodes"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter(|n| n["status"].as_str() == Some("online"))
        .collect();
    if nodes.is_empty() {
        println!("{}", ui::muted("no online nodes"));
        return Ok(0);
    }
    let mut rc = 0;
    for n in nodes {
        let id = n["id"].as_str().unwrap_or("?");
        println!("{}", ui::section(&format!("{id} ({container})")));
        let code = print_node_logs(g, id, &container, tail);
        if code != 0 && rc == 0 {
            rc = code;
        }
    }
    Ok(rc)
}

/// One node's container log lines, via the gateway's node-agent proxy.
/// Content goes to stdout so a pipe stays pure; the failure note does not.
fn print_node_logs(g: &Globals, node_id: &str, container: &str, tail: u64) -> i32 {
    let path = format!("/api/logs/node/{node_id}/{container}?tail={tail}");
    let body = match crate::http::get_json_try(g, &path, true, 30) {
        Ok(b) => b,
        Err(e) => {
            ui::failed(&format!("{node_id}: {e}"), None);
            return 1;
        }
    };
    if let Some(err) = body["error"].as_str() {
        ui::failed(&format!("{node_id}: {err}"), None);
        return 1;
    }
    match body["logs"].as_array() {
        Some(lines) => {
            for l in lines {
                if let Some(t) = l.as_str() {
                    println!("{t}");
                }
            }
            0
        }
        // Absence is not emptiness: a body with no `logs` key is a
        // contract break, not a quiet container.
        None => {
            ui::failed(
                &format!("{node_id}: the gateway returned no `logs` array for {container}"),
                None,
            );
            1
        }
    }
}

/// `noo cluster restart-agent NODE` —
/// POST /api/cluster/nodes/{node}/restart-agent (gateway proxies to the
/// node-agent's /restart; the agent re-registers on the way back up).
pub fn cluster_restart_agent(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [node] = args else { return Err(Unhandled) };
    if node.starts_with('-') {
        return Err(Unhandled);
    }
    let resp = post_json(
        g,
        &format!("/api/cluster/nodes/{}/restart-agent", super::urlencode(node)),
        &serde_json::json!({}),
        true,
        30,
    );
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    ui::done(resp["message"].as_str().unwrap_or("agent restart triggered"));
    Ok(0)
}

/// `noo cluster down BACKEND [--node NODE] [-y/--yes]` —
/// POST /api/cluster/backends/stop. Stops BACKEND on NODE, or on ALL nodes
/// when --node is omitted (Python parity: `node_id` travels as null).
/// Destructive → confirms first ("stop backend {backend} on {node|all
/// nodes}?", exactly Python's prompt); `--yes` skips, and unlike Python a
/// --json or non-TTY invocation errors instead of blocking on the prompt.
pub fn cluster_down(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut backend: Option<String> = None;
    let mut node: Option<String> = None;
    let mut yes = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--node" => node = Some(iter.next().ok_or(Unhandled)?.clone()),
            "-y" | "--yes" => yes = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t if backend.is_none() => backend = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let Some(backend) = backend else { return Err(Unhandled) };

    let target = match &node {
        Some(n) => format!("{backend} on {n}"),
        None => format!("{backend} on all nodes"),
    };
    super::confirm_destructive(g, yes, "stop backend", &target);

    let resp = post_json(
        g,
        "/api/cluster/backends/stop",
        &serde_json::json!({"backend": backend, "node_id": node}),
        true,
        60,
    );
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    if resp["status"].as_str() == Some("not_running") {
        ui::warned(&format!("{backend} not running on any nodes"));
    } else {
        // The stop route answers {status, backend, node_id} — it has never
        // sent `stopped_count`, so this printed "Stopped X on null node(s)".
        // Report the node and status the gateway actually returned.
        let status = resp["status"].as_str().unwrap_or("unknown");
        match resp["node_id"].as_str() {
            Some(n) => ui::done(&format!("stop {backend} on {n}: {}", ui::state(status))),
            None => ui::done(&format!("stop {backend}: {} (node not reported)", ui::state(status))),
        }
    }
    ui::guide(&[
        ("noo cluster status", "RUNNING column confirms the backend is gone from the node"),
        (&format!("noo cluster up {backend} <model>"), "brings it back on the scheduler's pick"),
    ]);
    Ok(0)
}

/// `noo cluster scale BACKEND -r/--replicas N [-m/--model M] [-y/--yes]` —
/// multi-step orchestration, faithful to the Python sequence:
///   1. GET /api/cluster/nodes → count nodes whose `running_backends`
///      (map or list) contains BACKEND.
///   2. Scale UP:   POST /api/cluster/backends/start ×(N-current) with
///      {backend, model}; warn + stop trying on the first failure.
///      No confirm (matches Python — starting replicas isn't destructive).
///   3. Scale DOWN: confirm ("scale down {backend} by {k} replica(s)?"),
///      then POST /api/cluster/backends/stop per least-loaded node
///      (sorted by the `load` field ascending); warn + continue per node.
/// Exit code stays 0 on per-replica warnings (Python parity); `--json`
/// emits a `{backend, current_replicas, target_replicas, started, stopped,
/// errors}` summary (Python has no JSON mode here).
pub fn cluster_scale(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut backend: Option<String> = None;
    let mut replicas: Option<i64> = None;
    let mut model = "default".to_string();
    let mut yes = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-r" | "--replicas" => {
                replicas = Some(iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?)
            }
            "-m" | "--model" => model = iter.next().ok_or(Unhandled)?.clone(),
            "-y" | "--yes" => yes = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t if backend.is_none() => backend = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let Some(backend) = backend else { return Err(Unhandled) };
    // --replicas is required in Python; missing → let Python print the usage error.
    let Some(replicas) = replicas else { return Err(Unhandled) };

    let body = get_json(g, "/api/cluster/nodes", true, 10);
    let empty = Vec::new();
    let mut with_backend: Vec<&serde_json::Value> = body["nodes"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter(|n| match &n["running_backends"] {
            serde_json::Value::Object(m) => m.contains_key(&backend),
            serde_json::Value::Array(a) => a.iter().any(|b| b.as_str() == Some(backend.as_str())),
            _ => false,
        })
        .collect();
    let current = with_backend.len() as i64;

    if !g.json {
        print!("{}", ui::kv(&[("current replicas", current.to_string()), ("target replicas", replicas.to_string())]));
    }

    let mut started: Vec<serde_json::Value> = Vec::new();
    let mut stopped: Vec<serde_json::Value> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    if replicas > current {
        let to_start = replicas - current;
        if !g.json {
            ui::step(&format!("scaling up by {to_start}"));
        }
        let start_body = serde_json::json!({"backend": backend, "model": model});
        for i in 0..to_start {
            match post_json_try(g, "/api/cluster/backends/start", &start_body, true, 60) {
                Ok(resp) => {
                    if !g.json {
                        println!("{}", ui::sub(&ui::status_line(Glyph::Ok, &format!(
                            "started replica on {}",
                            resp["node_hostname"].as_str().unwrap_or("?")
                        ))));
                    }
                    started.push(resp);
                }
                Err(e) => {
                    let msg = format!("could not start replica {}: {e}", i + 1);
                    if !g.json {
                        println!("{}", ui::sub(&ui::status_line(Glyph::Err, &msg)));
                    }
                    errors.push(msg);
                    break; // Python parity: give up after the first failed start
                }
            }
        }
    } else if replicas < current {
        let to_stop = (current - replicas) as usize;
        super::confirm_destructive(
            g,
            yes,
            "scale down",
            &format!("{backend} by {to_stop} replica(s)"),
        );
        if !g.json {
            ui::step(&format!("scaling down by {to_stop}"));
        }
        // Stop least-loaded nodes first (Python sorts by `load` ascending).
        with_backend.sort_by(|a, b| {
            let la = a["load"].as_f64().unwrap_or(0.0);
            let lb = b["load"].as_f64().unwrap_or(0.0);
            la.partial_cmp(&lb).unwrap_or(std::cmp::Ordering::Equal)
        });
        for n in with_backend.iter().take(to_stop) {
            let id = n["id"].as_str().unwrap_or("?");
            let stop_body = serde_json::json!({"backend": backend, "node_id": n["id"]});
            match post_json_try(g, "/api/cluster/backends/stop", &stop_body, true, 60) {
                Ok(resp) => {
                    if !g.json {
                        println!("{}", ui::sub(&ui::status_line(Glyph::Ok, &format!("stopped replica on {id}"))));
                    }
                    stopped.push(resp);
                }
                Err(e) => {
                    let msg = format!("failed to stop on {id}: {e}");
                    if !g.json {
                        println!("{}", ui::sub(&ui::status_line(Glyph::Err, &msg)));
                    }
                    errors.push(msg);
                }
            }
        }
    } else if !g.json {
        ui::done("already at target replica count");
    }

    if !g.json && replicas != current {
        let reached = current + started.len() as i64 - stopped.len() as i64;
        if errors.is_empty() {
            ui::close_done(&format!("{backend} at {reached} replica(s)"));
        } else {
            ui::close_warned(&format!("{backend} at {reached} replica(s), target {replicas} — {} error(s)", errors.len()));
        }
        ui::guide(&[
            ("noo cluster status", "RUNNING column shows where each replica landed"),
            (&format!("noo cluster scale {backend} --replicas {replicas}"), "re-run to converge if any replica failed"),
        ]);
    }

    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "backend": backend,
                "current_replicas": current,
                "target_replicas": replicas,
                "started": started,
                "stopped": stopped,
                "errors": errors,
            })
        );
    }
    Ok(0)
}

/// `noo cluster up BACKEND MODEL [--node NODE] [--replicas N]` —
/// POST /api/cluster/backends/start, once per replica (Python parity).
/// NOTE: legacy imperative path — the desired-state reconciler
/// (`noo cluster place`) is the preferred way to run persistent backends.
pub fn cluster_up(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positional: Vec<String> = Vec::new();
    let mut node: Option<String> = None;
    let mut replicas: u64 = 1;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--node" => node = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--replicas" => {
                replicas = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => positional.push(t.to_string()),
        }
    }
    let [backend, model] = positional.as_slice() else { return Err(Unhandled) };
    let mut body = serde_json::json!({"backend": backend, "model": model});
    if let Some(nid) = &node {
        body["node_id"] = serde_json::json!(nid);
    }
    let mut responses: Vec<serde_json::Value> = Vec::new();
    for _ in 0..replicas.max(1) {
        // Failure exits here with the typed code (5 on gateway error) —
        // partial-success output for earlier replicas already printed.
        let resp = post_json(g, "/api/cluster/backends/start", &body, true, 60);
        if g.json {
            responses.push(resp);
            continue;
        }
        let mut label = resp["node_hostname"]
            .as_str()
            .or_else(|| resp["node_id"].as_str())
            .unwrap_or("?")
            .to_string();
        if let Some(ip) = resp["ip_address"].as_str().filter(|s| !s.is_empty()) {
            label = format!("{label} ({ip})");
        }
        ui::done(&format!("started {backend} ({model}) on {label}"));
    }
    if g.json {
        if responses.len() == 1 {
            println!("{}", responses[0]);
        } else {
            println!("{}", serde_json::Value::Array(responses));
        }
    }
    Ok(0)
}

// ── Batch 3 helpers ─────────────────────────────────────────────────

/// `secrets.token_urlsafe(nbytes)` parity: base64url(/dev/urandom) with `=`
/// stripped (32 bytes → 43 chars). Same primitive the onboard wizard uses;
/// duplicated here to avoid coupling the `commands` and `onboard` modules.
fn token_urlsafe(nbytes: usize) -> String {
    use std::io::Read as _;
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut buf = vec![0u8; nbytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("read /dev/urandom");
    let mut out = String::with_capacity(buf.len().div_ceil(3) * 4);
    for chunk in buf.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        }
    }
    out
}

/// Online nodes from the gateway (parity with Python `_get_online_nodes`).
pub(crate) fn online_nodes(g: &Globals) -> Vec<serde_json::Value> {
    let body = get_json(g, "/api/cluster/nodes", true, 10);
    body["nodes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|n| n["status"].as_str() == Some("online"))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Spawn a subprocess with INHERITED stdio (streams live, propagates rc) —
/// the same pattern as `run_ssh`, for scp/ssh transfers.
pub(crate) fn spawn_inherited(g: &Globals, program: &str, args: &[String]) -> i32 {
    if g.verbose {
        eprintln!("{program} {}", args.join(" "));
    }
    match Command::new(program).args(args).status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "subprocess_failed",
            &format!("failed to spawn {program}: {e}"),
            None,
        ),
    }
}

// ── init-secret (LOCAL crypto, no gateway) ────────────

/// `noo cluster init-secret` — print a fresh `token_urlsafe(32)` cluster
/// secret (LOCAL; parity with `cluster_auth.generate_cluster_secret`). No
/// gateway call. `--json` emits `{"secret": …}` (the Python version only
/// console-prints).
pub fn cluster_init_secret(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let secret = token_urlsafe(32);
    if g.json {
        println!("{}", serde_json::json!({ "secret": secret }));
        return Ok(0);
    }
    // --quiet: only the secret (guide §7). Narration around it is gated.
    if !ui::quiet() {
        println!("{}", ui::header("cluster secret", None));
    }
    ui::value(&secret);
    if !ui::quiet() {
        println!();
        println!("  {}", ui::muted("add this to your controller .env and worker .env files:"));
        println!("  {}", ui::cmd(&format!("NOO_CLUSTER_SECRET={secret}")));
        println!("  {}", ui::muted("if NOO_CLUSTER_SECRET is unset, the gateway rejects node-agent calls (it does not fall back to open)"));
    }
    ui::guide(&[
        ("noo security secrets absorb-files", "stores the value in the encrypted secrets file instead of a plain .env"),
        ("noo cluster push-secrets", "converges every worker onto the controller's value"),
    ]);
    Ok(0)
}

// ── assign (scheduler dispatch) ─────────────────────────────────────

/// Map a priority word to the scheduler's numeric scale, or parse a number.
///
/// The queue is a Redis sorted set scored `-priority`, so HIGHER runs sooner
/// (`scheduler_engine.rs:454`). The route's own default is 5.
fn assign_priority(raw: &str) -> Option<i64> {
    match raw {
        "low" => Some(3),
        "medium" | "normal" => Some(5),
        "high" => Some(8),
        n => n.parse::<i64>().ok(),
    }
}

/// `noo cluster assign TASK [--node N] [--backend B] [--priority P]
/// [--model M] [--dry-run] [--async]` — CHOOSE a node, then PIN the task to
/// it.
///
/// The two halves are the point. Selection is local and deterministic: the
/// least-loaded online node, after the `--node` / `--backend` filters.
/// Execution then submits an `inference` job with `force_node` set to that
/// same node, so the box named by `--dry-run` is the box that runs the work.
///
/// It used to POST `/api/chat/completions` — Python's endpoint, which this
/// gateway has never served (it serves `/v1/chat/completions`), so every
/// non-dry-run invocation was an honest 404. Repointing it at the chat route
/// would not have been enough: the coordinator resolves its own backend, so
/// the selected node would have been decoration. `/api/jobs/submit` takes
/// `force_node` and the scheduler dispatches to exactly that node
/// (`admin.rs:1391`, `scheduler_engine.rs`), which is what "assign" claims to
/// do. Same rail as `noo jobs run --node`; assign is the version that picks
/// the node for you.
pub fn cluster_assign(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut task: Option<String> = None;
    let mut node: Option<String> = None;
    let mut backend: Option<String> = None;
    let mut model: Option<String> = None;
    let mut priority_raw = "medium".to_string();
    let mut dry_run = false;
    let mut async_mode = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--node" => node = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--backend" => backend = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--model" => model = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--priority" => priority_raw = iter.next().ok_or(Unhandled)?.clone(),
            "--dry-run" => dry_run = true,
            "--async" | "-a" => async_mode = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t if task.is_none() => task = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let Some(task) = task else { return Err(Unhandled) };
    let Some(priority) = assign_priority(&priority_raw) else {
        fail(
            g.json,
            ExitCode::Generic,
            "bad_priority",
            &format!("Unknown priority '{priority_raw}' — use low, medium, high, or a number"),
            None,
        );
    };

    // ── Select. Identical for dry-run and execute: the printed decision and
    // the pinned node come from the same code path, never two that can drift.
    let mut nodes = online_nodes(g);
    if nodes.is_empty() {
        fail(g.json, ExitCode::Generic, "no_nodes", "No online nodes available", None);
    }
    if let Some(want) = &node {
        nodes.retain(|n| n["id"].as_str() == Some(want) || n["hostname"].as_str() == Some(want));
        if nodes.is_empty() {
            fail(
                g.json,
                ExitCode::Generic,
                "node_not_found",
                &format!("Node '{want}' not found or offline"),
                None,
            );
        }
    }
    if let Some(b) = &backend {
        let matching: Vec<serde_json::Value> = nodes
            .iter()
            .filter(|n| running_backends_contains(n, b))
            .cloned()
            .collect();
        if !matching.is_empty() {
            nodes = matching;
        } else if !g.json {
            ui::warned(&format!("no nodes currently running {b}"));
        }
    }
    nodes.sort_by(|a, b| {
        let la = a["load"].as_f64().unwrap_or(1.0);
        let lb = b["load"].as_f64().unwrap_or(1.0);
        la.partial_cmp(&lb).unwrap_or(std::cmp::Ordering::Equal)
    });
    let selected = nodes[0].clone();
    let selected_id = selected["id"].as_str().unwrap_or_default().to_string();
    if selected_id.is_empty() {
        fail(
            g.json,
            ExitCode::Generic,
            "node_without_id",
            "Selected node has no id — cannot pin a job to it",
            None,
        );
    }

    if dry_run {
        if g.json {
            println!(
                "{}",
                serde_json::json!({
                    "dry_run": true,
                    "selected": selected,
                    "backend": backend.clone().unwrap_or_else(|| "auto".into()),
                    "priority": priority,
                })
            );
            return Ok(0);
        }
        let running = match &selected["running_backends"] {
            serde_json::Value::Object(m) => m.keys().cloned().collect::<Vec<_>>().join(", "),
            serde_json::Value::Array(a) => {
                a.iter().filter_map(|b| b.as_str()).collect::<Vec<_>>().join(", ")
            }
            _ => String::new(),
        };
        println!("{}", ui::header("routing decision", Some("dry run")));
        print!(
            "{}",
            ui::kv(&[
                ("node", selected_id.clone()),
                ("tier", format!("tier {}", selected["tier"].as_i64().unwrap_or(3))),
                ("gpu", selected["gpu_model"].as_str().unwrap_or("CPU").to_string()),
                ("load", format!("{:.0}%", selected["load"].as_f64().unwrap_or(0.0) * 100.0)),
                ("running backends", if running.is_empty() { ui::dash().to_string() } else { running }),
                ("backend", backend.as_deref().unwrap_or("auto").to_string()),
                ("priority", format!("{priority} ({priority_raw})")),
            ])
        );
        ui::guide(&[(
            "noo cluster assign <task> --priority <p>",
            "runs it, pinned to the node named above",
        )]);
        return Ok(0);
    }

    // ── Execute. `force_node` is the whole reason this is a job and not a
    // chat completion: the coordinator picks its own backend, the scheduler
    // does not.
    let timeout = g.timeout_secs.unwrap_or(300);
    let mut payload = serde_json::json!({ "prompt": task });
    if let Some(m) = &model {
        payload["model"] = serde_json::json!(m);
    }
    let body = serde_json::json!({
        "type": "inference",
        "payload": payload,
        "priority": priority,
        "backend": backend,
        "force_node": selected_id,
        "timeout_sec": timeout,
    });
    // 30s is the SUBMIT timeout, not the job's: the route returns as soon as
    // the job is queued. `timeout_sec` above is what the job itself gets.
    let data = post_json(g, "/api/jobs/submit", &body, true, 30);
    let Some(job_id) = data["job_id"].as_str().map(str::to_string) else {
        fail(
            g.json,
            ExitCode::Generic,
            "bad_response",
            &format!("gateway returned no job_id: {data}"),
            None,
        );
    };

    if async_mode {
        if g.json {
            println!("{}", serde_json::json!({"job_id": job_id, "node": selected_id}));
        } else {
            ui::done(&format!("assigned to {selected_id}"));
            ui::value(&job_id);
            ui::guide(&[
                (&format!("noo jobs status {job_id} --wait"), "block until it finishes and print the result"),
                ("noo jobs list", "see it in the queue alongside everything else"),
            ]);
        }
        return Ok(0);
    }

    if !g.json {
        ui::step(&format!("job {job_id} assigned to {selected_id}, waiting for result"));
    }
    match super::jobs::poll_job(g, &job_id, timeout) {
        Some(job) => Ok(super::jobs::report_terminal_job(g, &job)),
        None => Ok(super::jobs::report_poll_timeout(g, &job_id, timeout)),
    }
}


/// True when a node's `running_backends` (map or list) contains `backend`.
fn running_backends_contains(n: &serde_json::Value, backend: &str) -> bool {
    match &n["running_backends"] {
        serde_json::Value::Object(m) => m.contains_key(backend),
        serde_json::Value::Array(a) => a.iter().any(|b| b.as_str() == Some(backend)),
        _ => false,
    }
}

// ── set-config / clear-cooldowns ────────────────────────────────────

/// Flags `set-config` used to take that no longer do anything. The message
/// names why, so a stale runbook gets an answer rather than a silent no-op.
fn retired_set_config_flag(flag: &str) -> Option<&'static str> {
    match flag {
        "--ssh-user" => Some("--ssh-user is retired: the controller no longer reaches nodes over SSH, so the value would be stored and never used"),
        _ => None,
    }
}

/// `noo cluster set-config NODE [--usage shared|dedicated|default] [--data-root P] [--models-dir P]
/// [--ip A] [--tier T] [--gpu-model G] [--vram-gb V]` —
/// PUT /api/cluster/nodes/{node}/config with only the provided keys (parity
/// with Python's non-None body build). Errors if nothing was passed.
pub fn cluster_set_config(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut node: Option<String> = None;
    let mut body = serde_json::Map::new();
    let mut policy = serde_json::Map::new();
    let mut clear_policy = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        macro_rules! next {
            () => {
                iter.next().ok_or(Unhandled)?.clone()
            };
        }
        match tok.as_str() {
            "--data-root" => {
                // The data root becomes this node's allowed host root, so only
                // a dedicated, conventional `noo` directory may be declared.
                let root = next!();
                let (macos, home) = crate::commands::data_root::infer_os(&root);
                if let Some((code, why)) = crate::commands::data_root::shape_problem(&root, macos, &home) {
                    fail(
                        g.json,
                        ExitCode::Usage,
                        "data_root_policy",
                        &format!("data root refused ({code}): {why}"),
                        Some("use /var/lib/noo, or a dedicated <data disk>/noo (macOS: ~/noomesh or /Volumes/<disk>/noo)"),
                    );
                }
                body.insert("data_root".into(), serde_json::json!(root));
            }
            "--models-dir" => {
                body.insert("models_dir".into(), serde_json::json!(next!()));
            }
            "--ssh-user" => fail(
                g.json,
                ExitCode::Usage,
                "ssh_user_retired",
                retired_set_config_flag("--ssh-user").unwrap_or("retired flag"),
                Some("nothing connects to a node over SSH any more; see `noo cluster show <node>` for what the controller uses"),
            ),
            "--ip" => {
                body.insert("ip_address".into(), serde_json::json!(next!()));
            }
            "--tier" => {
                let v: i64 = next!().parse().map_err(|_| Unhandled)?;
                body.insert("tier".into(), serde_json::json!(v));
            }
            "--gpu-model" => {
                body.insert("gpu_model".into(), serde_json::json!(next!()));
            }
            // Companion policy. Each flag sets one key
            // of the stored object; the gateway validates and merges onto
            // its default at read time. `--policy-default` clears the row's
            // policy so the node follows the gateway default again.
            "--min-battery" => {
                let v: f64 = next!().parse().map_err(|_| Unhandled)?;
                policy.insert("min_battery_pct".into(), serde_json::json!(v));
            }
            "--require-wifi" => {
                let v = match next!().as_str() { "true" | "yes" | "1" => true, "false" | "no" | "0" => false, _ => return Err(Unhandled) };
                policy.insert("require_wifi".into(), serde_json::json!(v));
            }
            "--block-thermal" => {
                let states: Vec<String> = next!().split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
                policy.insert("blocked_thermal_states".into(), serde_json::json!(states));
            }
            "--policy-default" => {
                clear_policy = true;
            }
            // The harness policy: whether the loop
            // follows this node's chat backend on its own.
            "--harness" => {
                let v = next!();
                if !matches!(v.as_str(), "auto" | "manual" | "off") {
                    fail(g.json, ExitCode::Usage, "bad_harness_policy", "--harness must be auto, manual or off", None);
                }
                body.insert("harness_policy".into(), serde_json::json!(v));
            }
            // The loop budget a task gets when it lands on this node and
            // named none; `default` clears it.
            "--loop-budget" => {
                let v = next!();
                if v == "default" {
                    body.insert("default_loop_budget".into(), serde_json::Value::Null);
                } else {
                    let n: i64 = v.parse().map_err(|_| Unhandled)?;
                    if !(1..=500).contains(&n) {
                        fail(g.json, ExitCode::Usage, "bad_loop_budget", "--loop-budget must be 1..=500, or `default`", None);
                    }
                    body.insert("default_loop_budget".into(), serde_json::json!(n));
                }
            }
            "--vram-gb" => {
                let v: f64 = next!().parse().map_err(|_| Unhandled)?;
                body.insert("vram_gb".into(), serde_json::json!(v));
            }
            // How much of the node a placement may assume: `shared` (someone
            // uses it too: ~25% of cores, one request at a time, more GPU
            // headroom) or `dedicated` (cores - 2, normal headroom).
            // `default` clears it: dedicated on the controller, shared
            // elsewhere.
            "--usage" => {
                let v = next!();
                match v.as_str() {
                    "shared" | "dedicated" => body.insert("usage_profile".into(), serde_json::json!(v)),
                    "default" => body.insert("usage_profile".into(), serde_json::Value::Null),
                    _ => fail(g.json, ExitCode::Usage, "bad_usage_profile", "--usage must be shared, dedicated or default", None),
                };
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t if node.is_none() => node = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let Some(node) = node else { return Err(Unhandled) };
    if clear_policy && !policy.is_empty() {
        fail(g.json, ExitCode::Usage, "policy_conflict",
            "--policy-default clears the stored companion policy; do not combine it with --min-battery / --require-wifi / --block-thermal", None);
    }
    if clear_policy {
        body.insert("companion_policy".into(), serde_json::Value::Null);
    } else if !policy.is_empty() {
        body.insert("companion_policy".into(), serde_json::Value::Object(policy));
    }
    if body.is_empty() {
        fail(
            g.json,
            ExitCode::Generic,
            "nothing_to_set",
            "Nothing to set — pass at least one option",
            Some("e.g. --data-root <path> / --ip <ip> / --tier <n> / --min-battery <pct>"),
        );
    }
    // Asked BEFORE the body is handed to the request, which consumes it.
    let needs_bundle = ["data_root", "models_dir"].iter().any(|k| body.contains_key(*k));
    let resp = put_json(
        g,
        &format!("/api/cluster/nodes/{}/config", super::urlencode(&node)),
        &serde_json::Value::Object(body),
        true,
        10,
    );
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    // A path change is NOT a reconcile. The node declares which host roots a
    // controller-supplied path may live under from the env vars its BUNDLE
    // renders, so a new data root only becomes legal on the node once a bundle
    // carries it. Saying "agent reconciles within 5 min" for these two flags
    // sent the operator away believing a change had landed, and what actually
    // happened was `reconcile.models_dir_refused` on the node naming the old
    // roots (host3, 2026-09-12).
    if needs_bundle {
        ui::done(&format!("{node}: config updated — a path change needs a BUNDLE, not a reconcile"));
        ui::guide(&[(
            &format!("noo cluster provision {node} --wait"),
            "renders the new path into the node's env, which is what makes it legal there",
        )]);
    } else {
        ui::done(&format!("{node}: config updated — agent reconciles within 5 min"));
    }
    Ok(0)
}

/// `noo cluster clear-cooldowns` —
/// POST /api/cluster/backends/clear-cooldowns. Clears backend auto-start
/// backoff for ALL nodes: the gateway has no per-node form, so the command
/// takes no node argument.
pub fn cluster_clear_cooldowns(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    // The gateway clears every node's cooldowns and ignores a node filter,
    // so a node argument would only imply a scope that is not applied.
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let resp = post_json(g, "/api/cluster/backends/clear-cooldowns", &serde_json::json!({}), true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let cleared = resp["cleared"].as_i64().unwrap_or(0);
    ui::done(&format!("cleared {cleared} cooldown entries for all nodes"));
    Ok(0)
}

// ── add-companion / add-monitor (self-register via gateway) ─────────

/// `noo cluster add-companion NODE_ID [--platform P] [--hostname H] [--ip A]
/// [--sensors s,s] [--backends b,b] [--battery N] [--network T]
/// [--npu-tops N] [--app-version V]` — register a Tier-5 companion device
/// via POST /api/cluster/nodes/register, then send an initial heartbeat.
pub fn cluster_add_companion(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut node_id: Option<String> = None;
    let mut platform = "android".to_string();
    let mut hostname: Option<String> = None;
    let mut ip = "0.0.0.0".to_string();
    let mut sensors = String::new();
    let mut backends = "llamacpp".to_string();
    let mut battery = 100.0_f64;
    let mut network = "wifi".to_string();
    let mut npu_tops = 0.0_f64;
    let mut app_version = "cli-manual".to_string();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        macro_rules! next {
            () => {
                iter.next().ok_or(Unhandled)?.clone()
            };
        }
        match tok.as_str() {
            "-p" | "--platform" => platform = next!(),
            "--hostname" => hostname = Some(next!()),
            "--ip" => ip = next!(),
            "-s" | "--sensors" => sensors = next!(),
            "-b" | "--backends" => backends = next!(),
            "--battery" => battery = next!().parse().map_err(|_| Unhandled)?,
            "-n" | "--network" => network = next!(),
            "--npu-tops" => npu_tops = next!().parse().map_err(|_| Unhandled)?,
            "--app-version" => app_version = next!(),
            t if t.starts_with('-') => return Err(Unhandled),
            t if node_id.is_none() => node_id = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let Some(node_id) = node_id else { return Err(Unhandled) };
    let hostname = hostname.unwrap_or_else(|| node_id.clone());
    let sensor_list: Vec<String> =
        sensors.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).map(String::from).collect();
    let backend_list: Vec<String> =
        backends.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).map(String::from).collect();

    let payload = serde_json::json!({
        "node_id": node_id,
        "hostname": hostname,
        "ip_address": ip,
        "capabilities": {
            "cpu_cores": 4,
            "ram_gb": 4.0,
            "gpu_model": serde_json::Value::Null,
            "vram_gb": 0.0,
            "is_arm": platform == "android" || platform == "ios",
            "backends": backend_list,
            "tools": [],
            "tier": 5,
            "npu_tops": npu_tops,
            "platform": platform,
            "app_version": app_version,
            "sensors": sensor_list,
            "power_budget_watts": 5.0,
        },
    });
    let resp = post_json(g, "/api/cluster/nodes/register", &payload, true, 10);
    // Initial heartbeat (best-effort — device shows online).
    let hb = serde_json::json!({
        "load": 0.0,
        "running_backends": {},
        "battery_pct": battery,
        "is_charging": true,
        "network_type": network,
        "thermal_state": "nominal",
        "active_sensors": sensor_list,
    });
    let _ = post_json_try(
        g,
        &format!("/api/cluster/nodes/{}/heartbeat", super::urlencode(&node_id)),
        &hb,
        true,
        5,
    );
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    ui::done(&format!("companion device registered: {node_id} (platform={platform}, tier 5)"));
    print!("{}", ui::kv(&[
        ("  sensors", if sensor_list.is_empty() { ui::dash().to_string() } else { sensor_list.join(", ") }),
        ("  backends", backend_list.join(", ")),
    ]));
    Ok(0)
}

/// `noo cluster add-monitor NODE_ID [--hostname H] [--ip A] [--services s,s]`
/// — register a Tier-6 monitoring node via POST /api/cluster/nodes/register,
/// then send an initial heartbeat.
pub fn cluster_add_monitor(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut node_id: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut ip = "0.0.0.0".to_string();
    let mut services = String::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        macro_rules! next {
            () => {
                iter.next().ok_or(Unhandled)?.clone()
            };
        }
        match tok.as_str() {
            "--hostname" => hostname = Some(next!()),
            "--ip" => ip = next!(),
            "-s" | "--services" => services = next!(),
            t if t.starts_with('-') => return Err(Unhandled),
            t if node_id.is_none() => node_id = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let Some(node_id) = node_id else { return Err(Unhandled) };
    let hostname = hostname.unwrap_or_else(|| node_id.clone());
    let service_list: Vec<String> =
        services.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).map(String::from).collect();

    let payload = serde_json::json!({
        "node_id": node_id,
        "hostname": hostname,
        "ip_address": ip,
        "capabilities": {
            "cpu_cores": 4,
            "ram_gb": 2.0,
            "gpu_model": serde_json::Value::Null,
            "vram_gb": 0.0,
            "is_arm": true,
            "backends": [],
            "tools": service_list,
            "tier": 6,
        },
    });
    let resp = post_json(g, "/api/cluster/nodes/register", &payload, true, 10);
    let hb = serde_json::json!({"load": 0.0, "running_backends": {}});
    let _ = post_json_try(
        g,
        &format!("/api/cluster/nodes/{}/heartbeat", super::urlencode(&node_id)),
        &hb,
        true,
        5,
    );
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    ui::done(&format!("monitor node registered: {node_id} (tier 6)"));
    print!("{}", ui::kv(&[("  services", if service_list.is_empty() { ui::dash().to_string() } else { service_list.join(", ") })]));
    Ok(0)
}

// ── clean-node (RETIRED container-era verb) ─────────────────────────

/// `noo cluster clean-node` — RETIRED (fu72 #4). The old body root-SSHed
/// docker greps that match NOTHING on a pull-architecture node (native
/// systemd agent, no PAI containers), exited 0, printed "cleaned", then
/// DE-REGISTERED the node — a live box the operator now believed was gone.
/// The honest verbs replaced it; this stub names them instead of faking
/// success. (Not removed from dispatch: an old runbook hitting a missing
/// command gets "unknown command", which explains nothing.)
pub fn cluster_clean_node(g: &Globals, _args: &[String]) -> Result<i32, Unhandled> {
    fail(
        g.json,
        ExitCode::Generic,
        "retired_command",
        "clean-node is retired: it assumed container-era nodes and reported \
         success while doing nothing on a pull node (then de-registered it)",
        Some(
            "dismantle a node:      noo cluster teardown-node <name>\n  \
             forget a dead node:    noo cluster forget <name>\n  \
             node-side (orphaned):  sudo noo-deenroll",
        ),
    );
}

// ── sync-models (RETIRED misnomer, container-era) ───────────────────

/// `noo cluster sync-models` — RETIRED. It held the last ssh call site in
/// this crate — deliberately not spelled out here, so a future audit grepping
/// for one does not match this comment. Three separate things had already
/// killed it:
///
///   1. **The name was never true.** It pulled Docker IMAGES, not models —
///      `cli.py` says so in its own note. Images are `noo cluster
///      sync-images`, which ships controller-BUILT images over the artifact
///      rail; a node pulls PUBLISHED images itself when a backend starts.
///      Weights are `sync-model-files`, on the dispatch rail since #1182.
///   2. **The remote command assumed a repo and a venv** on the node
///      (`cd ~/pai-assistant && source venv/bin/activate`). Enrollment stopped
///      creating either when the agent became a host process; fu72 flagged it
///      then and said to retire it with the ansible era, which has since gone.
///   3. **It needed SSH**, which the fleet does not have.
///
/// Any one of those would make it fail; together they make it unrevivable.
/// Kept as a stub rather than deleted for the reason `clean-node` was: an old
/// runbook hitting a missing command gets "unknown command", which explains
/// nothing.
pub fn cluster_sync_models(g: &Globals, _args: &[String]) -> Result<i32, Unhandled> {
    fail(
        g.json,
        ExitCode::Generic,
        "retired_command",
        "sync-models is retired: despite the name it pulled docker IMAGES, \
         over SSH, into a repo checkout and venv that nodes no longer have",
        Some(
            "controller-built images:  noo cluster sync-images [<node>...]\n  \
             published images:         a node pulls its own when a backend starts\n  \
             model weights:            noo cluster sync-model-files <node> -m <file>\n  \
             what should be running:   noo cluster place / noo cluster desired",
        ),
    );
}

// ── exec / reconnect (retired stubs — the SSH lane is gone) ─────────

/// `noo cluster exec` — RETIRED 2026-09-11.
///
/// It only ever existed as a `noo-py` verb that ssh'd into the node and ran
/// a shell command. There is no rail replacement and that is deliberate:
/// the node-agent exposes named operations (`/start`, `/stop`, `/restart`,
/// `/pull`, `/clean`, `/logs/*`, skills) and NO arbitrary-exec endpoint. An
/// agent that ran whatever the controller sent would be the SSH lane again,
/// wearing an HTTP hat.
///
/// A stub rather than nothing, for the reason `clean-node` and `sync-models`
/// are stubs: an old runbook hitting a missing command gets "unknown
/// command", which explains nothing.
pub fn cluster_exec(g: &Globals, _args: &[String]) -> Result<i32, Unhandled> {
    fail(
        g.json,
        ExitCode::Generic,
        "retired_command",
        "cluster exec is retired: it ran a shell command on the node over SSH, \
         and the controller\u{2192}node SSH lane was removed 2026-09-11",
        Some(
            "container logs:      noo cluster logs <node> [<service>]\n               restart the agent:   noo cluster restart-agent <node>\n               stop/start backends: noo cluster up / down / place / unplace\n               remove containers:   noo cluster clean <node>\n               anything else:       run it ON the node — by design there is no \
             remote shell",
        ),
    );
}

/// `noo cluster reconnect` — RETIRED 2026-09-11.
///
/// The Python verb ssh'd into every node to rewrite the `noo-controller`
/// line in `/etc/hosts`. A node finds the controller through its own
/// enrolment config and MagicDNS now; when that is wrong, re-running the
/// enrolment paste on the node fixes it in place.
pub fn cluster_reconnect(g: &Globals, _args: &[String]) -> Result<i32, Unhandled> {
    fail(
        g.json,
        ExitCode::Generic,
        "retired_command",
        "cluster reconnect is retired: it rewrote /etc/hosts on every node over \
         SSH, and the controller\u{2192}node SSH lane was removed 2026-09-11",
        Some(
            "one flapping agent:   noo cluster restart-agent <node>\n               a node that moved:    re-run the enrolment paste on it (noo enroll \
             adapts in place)\n               a node that is gone:  noo cluster forget <node>",
        ),
    );
}

// ── sync-model-files (ship gguf weights via scp) ────────────────────

/// `noo cluster sync-model-files [NODE…] [-m/--model FILE]… [-u/--user U]
/// [--dry-run]` — ship gguf weights from the controller store to worker
/// nodes. Source = $MODELS_DIR else $NOO_DATA_ROOT/models (default
/// DEFAULT_DATA_ROOT/models). Per node: SSH-probe the node's own .env for its
/// MODELS_DIR/NOO_DATA_ROOT (read-only), then scp each file (streaming, with
/// a cheap same-size idempotence skip). `--dry-run` probes + prints only.
pub fn cluster_sync_model_files(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut want_nodes: Vec<String> = Vec::new();
    let mut want_models: Vec<String> = Vec::new();
    let mut dry_run = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-m" | "--model" => want_models.push(iter.next().ok_or(Unhandled)?.clone()),
            // `-u` chose an SSH account. There is no SSH account: the node
            // pulls its own copy. Refusing beats silently ignoring it.
            "-u" | "--user" => fail(
                g.json,
                ExitCode::Usage,
                "user_unsupported",
                "`--user` selected an SSH account; sync-model-files no longer pushes over SSH",
                Some("drop the flag — each node pulls from the model cache and verifies the digest"),
            ),
            "--dry-run" => dry_run = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => want_nodes.push(t.to_string()),
        }
    }

    // Resolve the controller store (env already carries .env via ensure_repo_env).
    // One resolver with `noo models fetch`, so the file it downloads is the
    // file this finds.
    let store = crate::commands::models_fetch::controller_store_dir();
    let store_path = PathBuf::from(&store);
    if !store_path.is_dir() {
        fail(g.json, ExitCode::Generic, "no_store", &format!("Controller model store not found: {store}"), None);
    }

    // Gather source files.
    let files: Vec<PathBuf> = if !want_models.is_empty() {
        let mut v = Vec::new();
        for m in &want_models {
            let p = store_path.join(m);
            if !p.exists() {
                fail(
                    g.json,
                    ExitCode::Generic,
                    "not_in_store",
                    &format!(
                        "Not in controller store: {} (store {store}, from MODELS_DIR, else NOO_DATA_ROOT/models)",
                        p.display()
                    ),
                    Some("download it into the store first: `noo models fetch <hf_repo> <file.gguf>` (uses the controller's HF token)"),
                );
            }
            v.push(p);
        }
        v
    } else {
        let mut v: Vec<PathBuf> = std::fs::read_dir(&store_path)
            .map(|rd| {
                rd.filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("gguf"))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    };
    if files.is_empty() {
        fail(g.json, ExitCode::Generic, "no_files", &format!("No .gguf files in controller store {store}"), None);
    }
    let total_mb: u64 = files.iter().filter_map(|f| f.metadata().ok()).map(|m| m.len()).sum::<u64>() / (1024 * 1024);
    println!("{}", ui::header("sync model files", Some(&format!("{store} · {} file(s) · {total_mb} MB", files.len()))));

    // Resolve targets: online nodes minus self, optionally filtered by NODE args.
    let my_id = std::env::var("NOO_CONTROLLER_NODE_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::process::Command::new("uname")
                .arg("-n")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        });
    let online = online_nodes(g);
    let targets: Vec<serde_json::Value> = online
        .into_iter()
        .filter(|n| {
            let id = n["id"].as_str().unwrap_or("");
            let host = n["hostname"].as_str().unwrap_or("");
            if id == my_id || host == my_id {
                return false;
            }
            want_nodes.is_empty()
                || want_nodes.iter().any(|w| w == id || w == host)
        })
        .collect();
    if targets.is_empty() {
        println!("{}", ui::muted("no target nodes"));
        return Ok(0);
    }

    // Delivery is the artifact rail: one `model_file` job per (node, file).
    // The node pulls from the model cache and verifies against the gateway's
    // manifest digest — the same control plane images and agent binaries
    // already use. This replaced scp over SSH (retired 2026-09-05); nothing
    // new was built for it beyond a caller for kind=gguf.
    //
    // Better than the push it replaced in three ways: it works on a node the
    // controller holds no key for (now every node), the digest is stated by
    // the manifest rather than assumed from the transport, and a file already
    // present with the right hash is a no-op rather than a re-transfer.
    if dry_run {
        println!("{}", ui::section("would dispatch"));
        for n in &targets {
            let nid = n["id"].as_str().unwrap_or("?");
            for f in &files {
                let fname = f.file_name().and_then(|x| x.to_str()).unwrap_or("?");
                println!("{}", ui::item(&format!("{nid}  {fname}")));
            }
        }
        ui::close_done(&format!(
            "{} job(s) would be dispatched",
            targets.len() * files.len()
        ));
        return Ok(0);
    }

    // Have the gateway hash each file BEFORE the jobs ask for it. The
    // manifest route hashes on first request; on 2026-10-10 a 3.3 GB GGUF on
    // the NFS store took 13.5 s, the node gave up first, and its job failed
    // until a retry 3 minutes later. Warming here makes the nodes' requests
    // cache hits. Best effort: a file still hashing when the budget ends is
    // dispatched anyway (the agent follows the gateway's 202s).
    println!("{}", ui::phase("digest"));
    for f in &files {
        let Some(fname) = f.file_name().and_then(|x| x.to_str()) else {
            continue;
        };
        let line = match warm_gguf_manifest(g, fname, MANIFEST_WARM_BUDGET) {
            ManifestWarm::Ready(sha) => ui::status_line(
                Glyph::Ok,
                &format!("{fname}  {}", ui::muted(&format!("sha256 {}…", &sha[..sha.len().min(12)]))),
            ),
            ManifestWarm::Hashing(_) => ui::status_line(
                Glyph::Warn,
                &format!("{fname}: the gateway is still hashing it — the nodes will wait for the digest"),
            ),
            ManifestWarm::Missing => ui::status_line(
                Glyph::Err,
                &format!(
                    "{fname}: the gateway's artifact store does not see it — is the gateway's \
                     NOO_ARTIFACT_GGUF_DIR mount the same directory as {store}?"
                ),
            ),
            ManifestWarm::Failed(why) => ui::status_line(Glyph::Warn, &format!("{fname}: digest not pre-computed ({why})")),
        };
        println!("{}", ui::sub(&line));
    }

    println!("{}", ui::phase("dispatch"));
    let mut failed = 0;
    let mut queued = 0;
    for n in &targets {
        let nid = n["id"].as_str().unwrap_or("?");
        println!("{}", ui::item(nid));
        for f in &files {
            let Some(fname) = f.file_name().and_then(|x| x.to_str()) else {
                continue;
            };
            let body = serde_json::json!({
                "type": "model_file",
                "force_node": nid,
                "payload": {"model": fname},
                // A 15 GB pull over a home LAN is not a 300s job.
                "timeout_sec": 5400,
            });
            match crate::http::post_json_try(g, "/api/jobs/submit", &body, true, 30) {
                Ok(v) => {
                    let jid = v["job_id"].as_str().or_else(|| v["id"].as_str()).unwrap_or("?");
                    println!("{}", ui::sub(&ui::status_line(Glyph::Ok, &format!("{fname}  {}", ui::muted(jid)))));
                    queued += 1;
                }
                Err(e) => {
                    println!("{}", ui::sub(&ui::status_line(Glyph::Err, &format!("{fname}: {e}"))));
                    failed += 1;
                }
            }
        }
    }

    println!();
    // Queued is not delivered. The jobs run asynchronously on each node, so
    // saying "synced" here would be a claim this command cannot make.
    if failed == 0 {
        ui::close_done(&format!("{queued} job(s) queued across {} node(s)", targets.len()));
        ui::guide(&[
            ("noo jobs list", "watch them run; each node pulls and verifies its own copy"),
        ]);
        Ok(0)
    } else {
        ui::close_failed(
            &format!("{queued} queued, {failed} could not be submitted"),
            Some("noo cluster sync-model-files"),
        );
        Ok(1)
    }
}

/// How long `sync-model-files` waits for the gateway to hash the files it is
/// about to ship. A 15 GB GGUF at ~100 MB/s is ~2.5 minutes.
pub(crate) const MANIFEST_WARM_BUDGET: std::time::Duration = std::time::Duration::from_secs(600);

/// What the gateway's artifact manifest route said about one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ManifestWarm {
    /// 200 with a digest: cached, so every node's request is instant.
    Ready(String),
    /// 202: hashing in the background; ask again after this many seconds.
    Hashing(u64),
    /// 404: the gateway's store does not have the file.
    Missing,
    /// Anything else (transport, 5xx, an older gateway's answer).
    Failed(String),
}

/// Classify one manifest answer. Pure, so the protocol is tested.
pub(crate) fn classify_manifest_answer(status: u16, body: &str) -> ManifestWarm {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    match status {
        200 => match v["sha256"].as_str() {
            Some(sha) if sha.len() == 64 => ManifestWarm::Ready(sha.to_ascii_lowercase()),
            _ => ManifestWarm::Failed("200 without a sha256".into()),
        },
        202 => ManifestWarm::Hashing(v["retry_after_secs"].as_u64().unwrap_or(5).clamp(1, 15)),
        404 => ManifestWarm::Missing,
        s => ManifestWarm::Failed(format!(
            "HTTP {s}{}",
            v["error"].as_str().map(|e| format!(": {e}")).unwrap_or_default()
        )),
    }
}

/// Path-escape a bare filename for the manifest route (RFC 3986 unreserved
/// characters pass through; everything else is %-encoded).
fn path_escape(name: &str) -> String {
    name.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Ask the gateway for a GGUF's manifest until it is ready or `budget`
/// runs out, which makes the gateway compute and cache the digest. Shared
/// by `sync-model-files` and anything else that places a file in the store.
pub(crate) fn warm_gguf_manifest(g: &Globals, name: &str, budget: std::time::Duration) -> ManifestWarm {
    let path = format!("/api/artifacts/manifest/gguf/{}", path_escape(name));
    let start = std::time::Instant::now();
    loop {
        let answer = match crate::http::request_try(g, "GET", &path, None, true, 30) {
            Ok((status, body)) => classify_manifest_answer(status, &body),
            Err(why) => ManifestWarm::Failed(why),
        };
        match answer {
            ManifestWarm::Hashing(secs) => {
                let wait = std::time::Duration::from_secs(secs);
                if start.elapsed() + wait > budget {
                    return ManifestWarm::Hashing(secs);
                }
                std::thread::sleep(wait);
            }
            other => return other,
        }
    }
}

// ── reconnect (fleet /etc/hosts controller-IP update via SSH) ───────

/// Node config PUT body from a seed-file node entry (key mapping + None
/// filtering, Python parity: `ip` → `ip_address`).
fn seed_node_body(cfg: &serde_json::Value) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    for (src, dst) in [
        ("data_root", "data_root"),
        ("models_dir", "models_dir"),
        ("ssh_user", "ssh_user"),
        ("ip", "ip_address"),
        ("tier", "tier"),
        ("gpu_model", "gpu_model"),
        ("vram_gb", "vram_gb"),
        ("companion_policy", "companion_policy"),
        ("harness_policy", "harness_policy"),
        ("default_loop_budget", "default_loop_budget"),
    ] {
        let v = &cfg[src];
        if !v.is_null() {
            body.insert(dst.to_string(), v.clone());
        }
    }
    serde_json::Value::Object(body)
}

/// Placement PUT body from a seed-file placement entry (Python parity:
/// `model` always present even when null; `tls` coerced to bool;
/// `state` → `desired_state` defaulting "running"; port when present,
/// image/env only when truthy).
fn seed_placement_body(p: &serde_json::Value) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    body.insert("model".into(), p["model"].clone());
    body.insert("tls".into(), serde_json::json!(p["tls"].as_bool().unwrap_or(false)));
    body.insert(
        "desired_state".into(),
        p["state"].as_str().map(serde_json::Value::from).unwrap_or_else(|| "running".into()),
    );
    if !p["port"].is_null() {
        body.insert("port".into(), p["port"].clone());
    }
    if p["image"].as_str().map(|s| !s.is_empty()).unwrap_or(false) {
        body.insert("image".into(), p["image"].clone());
    }
    if p["env"].as_object().map(|m| !m.is_empty()).unwrap_or(false) {
        body.insert("env".into(), p["env"].clone());
    }
    if let Some(r) = p["role"].as_str().filter(|r| !r.is_empty()) {
        body.insert("role".into(), serde_json::json!(r));
    }
    serde_json::Value::Object(body)
}

/// Seed-file node entry from a desired-config `node` record (export
/// direction; key order + None filtering match Python's dict literal).
fn seed_export_node(n: &serde_json::Value) -> serde_yaml::Value {
    let mut m = serde_yaml::Mapping::new();
    for (dst, src) in [
        ("ip", "ip_address"),
        ("ssh_user", "ssh_user"),
        ("tier", "tier"),
        ("data_root", "data_root"),
        ("models_dir", "models_dir"),
        ("gpu_model", "gpu_model"),
        ("vram_gb", "vram_gb"),
        ("companion_policy", "companion_policy"),
        ("harness_policy", "harness_policy"),
        ("default_loop_budget", "default_loop_budget"),
    ] {
        let v = &n[src];
        if !v.is_null() {
            if let Ok(yv) = serde_yaml::to_value(v) {
                m.insert(serde_yaml::Value::String(dst.to_string()), yv);
            }
        }
    }
    serde_yaml::Value::Mapping(m)
}

/// Seed-file placement entry from a desired-config `placements` record
/// (export direction; Python drops falsy `tls` and empty `env`).
fn seed_export_placement(nid: &str, p: &serde_json::Value) -> serde_yaml::Value {
    let mut m = serde_yaml::Mapping::new();
    let mut put = |k: &str, v: &serde_json::Value| {
        if !v.is_null() {
            if let Ok(yv) = serde_yaml::to_value(v) {
                m.insert(serde_yaml::Value::String(k.to_string()), yv);
            }
        }
    };
    put("node", &serde_json::json!(nid));
    put("backend", &p["backend"]);
    put("model", &p["model"]);
    put("port", &p["port"]);
    // `p.get("tls") or None` — false/absent is omitted.
    if p["tls"].as_bool() == Some(true) {
        put("tls", &serde_json::json!(true));
    }
    put("image", &p["image"]);
    // `p.get("env") or None` — empty map is omitted.
    if p["env"].as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        put("env", &p["env"]);
    }
    put("state", &p["desired_state"]);
    // A role other than the default (chat) is part of the placement's key; a
    // seed with two roles of one backend would otherwise collide.
    if let Some(r) = p["role"].as_str().filter(|r| !r.is_empty() && *r != "chat" && *r != "harness") {
        put("role", &serde_json::json!(r));
    }
    serde_yaml::Value::Mapping(m)
}

/// Model-class PUT body from a seed-file entry:
/// `{aliases: [..], pool?: true, candidates: [{node, backend, model?, degraded?}]}`.
/// `model` is sent only when given — absent means the placement's model —
/// and `degraded` and `pool` only when true.
fn seed_model_class_body(spec: &serde_json::Value) -> serde_json::Value {
    let empty = Vec::new();
    let candidates: Vec<serde_json::Value> = spec["candidates"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|c| {
            let node = c["node"].as_str()?;
            let backend = c["backend"].as_str()?;
            let mut out = serde_json::json!({"node": node, "backend": backend});
            if let Some(m) = c["model"].as_str().filter(|m| !m.is_empty()) {
                out["model"] = serde_json::json!(m);
            }
            if c["degraded"].as_bool() == Some(true) {
                out["degraded"] = serde_json::json!(true);
            }
            Some(out)
        })
        .collect();
    let aliases: Vec<serde_json::Value> = spec["aliases"].as_array().cloned().unwrap_or_default();
    let mut body = serde_json::json!({"candidates": candidates, "aliases": aliases});
    if spec["pool"].as_bool() == Some(true) {
        body["pool"] = serde_json::json!(true);
    }
    body
}

/// Seed-file `model_classes` map from `GET /api/cluster/model-classes`:
/// declared classes only, each `{aliases?, candidates: [{node, backend,
/// model?, degraded?}]}`. A candidate's `model` is written only when the
/// DECLARATION carried one (`declared_model`); a candidate that meant "the
/// placement's model" is exported without one, so the seed file never
/// restates a placement.
fn seed_export_model_classes(classes: &serde_json::Value) -> serde_yaml::Mapping {
    let empty = Vec::new();
    let mut out = serde_yaml::Mapping::new();
    let aliases_of = |name: &str| -> Vec<serde_yaml::Value> {
        classes["aliases"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .filter(|a| a["class"].as_str() == Some(name) && a["builtin"].as_bool() != Some(true))
            .filter_map(|a| a["alias"].as_str().map(|s| serde_yaml::Value::String(s.to_string())))
            .collect()
    };
    for c in classes["classes"].as_array().unwrap_or(&empty) {
        if c["declared"].as_bool() != Some(true) {
            continue;
        }
        let Some(name) = c["name"].as_str() else { continue };
        let mut spec = serde_yaml::Mapping::new();
        let aliases = aliases_of(name);
        if !aliases.is_empty() {
            spec.insert("aliases".into(), serde_yaml::Value::Sequence(aliases));
        }
        if c["pool"].as_bool() == Some(true) {
            spec.insert("pool".into(), serde_yaml::Value::Bool(true));
        }
        let cands: Vec<serde_yaml::Value> = c["candidates"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(|cand| {
                let mut m = serde_yaml::Mapping::new();
                m.insert("node".into(), serde_yaml::Value::String(cand["node_id"].as_str().unwrap_or("").into()));
                m.insert("backend".into(), serde_yaml::Value::String(cand["backend"].as_str().unwrap_or("").into()));
                if let Some(model) = cand["declared_model"].as_str().filter(|m| !m.is_empty()) {
                    m.insert("model".into(), serde_yaml::Value::String(model.into()));
                }
                if cand["degraded"].as_bool() == Some(true) {
                    m.insert("degraded".into(), serde_yaml::Value::Bool(true));
                }
                serde_yaml::Value::Mapping(m)
            })
            .collect();
        spec.insert("candidates".into(), serde_yaml::Value::Sequence(cands));
        out.insert(serde_yaml::Value::String(name.to_string()), serde_yaml::Value::Mapping(spec));
    }
    out
}

/// `noo cluster seed [-f/--file PATH] [--export] [--dry-run]` — apply (or
/// export) the cluster's desired state from a local seed file. The default
/// path is relative to the CURRENT directory (Python parity).
pub fn cluster_seed(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut file = PathBuf::from("config/cluster-seed.yaml");
    let (mut export, mut dry_run) = (false, false);
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-f" | "--file" => file = PathBuf::from(iter.next().ok_or(Unhandled)?),
            "--export" => export = true,
            "--dry-run" => dry_run = true,
            _ => return Err(Unhandled),
        }
    }
    // Per-item progress is narration: stderr in both modes (the human path used to print it on stdout).

    if export {
        // Node list is the one hard dependency — failures exit with the
        // typed transport/auth/remote codes (Python: fatal, exit 1).
        let body = crate::http::get_json(g, "/api/cluster/nodes", true, 10);
        let empty = Vec::new();
        let mut node_ids: Vec<String> = body["nodes"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .filter_map(|n| n["node_id"].as_str().or_else(|| n["id"].as_str()))
            .map(str::to_string)
            .collect();
        node_ids.sort();
        node_ids.dedup();

        let mut nodes_out = serde_yaml::Mapping::new();
        let mut placements_out: Vec<serde_yaml::Value> = Vec::new();
        for nid in &node_ids {
            let data = match crate::http::get_json_try(
                g,
                &format!("/api/cluster/nodes/{}/desired-config", super::urlencode(nid)),
                true,
                10,
            ) {
                Ok(d) => d,
                Err(e) => {
                    ui::warned(&format!("{nid}: could not fetch desired config ({e}); skipped"));
                    continue;
                }
            };
            let n = &data["node"];
            if !n.is_null() {
                nodes_out.insert(serde_yaml::Value::String(nid.clone()), seed_export_node(n));
            }
            for p in data["placements"].as_array().unwrap_or(&empty) {
                placements_out.push(seed_export_placement(nid, p));
            }
        }
        let node_count = nodes_out.len();
        let mut doc = serde_yaml::Mapping::new();
        doc.insert("nodes".into(), serde_yaml::Value::Mapping(nodes_out));
        doc.insert("placements".into(), serde_yaml::Value::Sequence(placements_out));
        // Declared model classes. Derived ones are what the
        // fleet serves and are not a declaration, so they are not exported.
        if let Some(classes) = crate::http::get_json_opt(g, "/api/cluster/model-classes", true, 15) {
            let out = seed_export_model_classes(&classes);
            if !out.is_empty() {
                doc.insert("model_classes".into(), serde_yaml::Value::Mapping(out));
            }
        }
        let text = serde_yaml::to_string(&serde_yaml::Value::Mapping(doc)).unwrap_or_default();
        if let Some(parent) = file.parent().filter(|p| !p.as_os_str().is_empty()) {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&file, text) {
            fail(
                g.json,
                ExitCode::Generic,
                "write_failed",
                &format!("could not write {}: {e}", file.display()),
                None,
            );
        }
        if g.json {
            println!(
                "{}",
                serde_json::json!({"status": "ok", "action": "export", "nodes": node_count, "file": file.display().to_string()})
            );
        } else {
            ui::done(&format!("exported desired state for {node_count} node(s)"));
            ui::value(&file.display().to_string());
            ui::guide(&[
                (&format!("noo cluster seed -f {}", file.display()), "re-applies this snapshot to the fleet"),
                (&format!("noo cluster seed -f {} --dry-run", file.display()), "shows what would change first"),
            ]);
        }
        return Ok(0);
    }

    if !file.is_file() {
        fail(
            g.json,
            ExitCode::Generic,
            "seed_file_not_found",
            &format!(
                "Seed file not found: {} — copy config/cluster-seed.yaml.example and fill in \
                 your nodes, or snapshot a live cluster with --export",
                file.display()
            ),
            None,
        );
    }
    let doc: serde_json::Value = std::fs::read_to_string(&file)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_yaml::from_str::<serde_yaml::Value>(&t).map_err(|e| e.to_string()))
        .and_then(|y| serde_json::to_value(&y).map_err(|e| e.to_string()))
        .unwrap_or_else(|e| {
            fail(
                g.json,
                ExitCode::Generic,
                "seed_file_invalid",
                &format!("Failed to parse {}: {e}", file.display()),
                None,
            )
        });

    // Warn-and-continue per item, Python parity: apply as much of the seed
    // as possible; item failures are printed, the command still exits 0.
    let mut applied = 0usize;
    let mut failed = 0usize;
    let empty_map = serde_json::Map::new();
    let node_map = doc["nodes"].as_object().unwrap_or(&empty_map);
    if !g.json && !node_map.is_empty() {
        println!("{}", ui::phase("node config"));
    }
    for (nid, cfg) in node_map {
        let body = seed_node_body(cfg);
        if dry_run {
            println!("{}", ui::status_line(Glyph::Step, &format!("would set-config {nid}: {body}")));
            continue;
        }
        match crate::http::put_json_try(
            g,
            &format!("/api/cluster/nodes/{}/config", super::urlencode(nid)),
            &body,
            true,
            10,
        ) {
            Ok(_) => {
                ui::done(&format!("{nid}: config applied"));
                applied += 1;
            }
            Err(e) => {
                println!("{}", ui::status_line(Glyph::Err, &format!("{nid}: config failed ({e})")));
                failed += 1;
            }
        }
    }
    let empty_list = Vec::new();
    let placements = doc["placements"].as_array().unwrap_or(&empty_list);
    if !g.json && !placements.is_empty() {
        println!("{}", ui::phase("placements"));
    }
    for p in placements {
        let (Some(nid), Some(backend)) = (p["node"].as_str(), p["backend"].as_str()) else {
            ui::warned(&format!("skipped placement missing node/backend: {p}"));
            continue;
        };
        let body = seed_placement_body(p);
        if dry_run {
            println!("{}", ui::status_line(Glyph::Step, &format!("would place {nid}/{backend}: {body}")));
            continue;
        }
        match crate::http::put_json_try(
            g,
            &format!(
                "/api/cluster/nodes/{}/placements/{}",
                super::urlencode(nid),
                super::urlencode(backend)
            ),
            &body,
            true,
            10,
        ) {
            Ok(_) => {
                ui::done(&format!(
                    "{nid}: {backend} → {} placed",
                    p["model"].as_str().unwrap_or("None")
                ));
                applied += 1;
            }
            Err(e) => {
                println!("{}", ui::status_line(Glyph::Err, &format!("{nid}/{backend}: placement failed ({e})")));
                failed += 1;
            }
        }
    }
    let empty_classes = serde_json::Map::new();
    let classes = doc["model_classes"].as_object().unwrap_or(&empty_classes);
    if !g.json && !classes.is_empty() {
        println!("{}", ui::phase("model classes"));
    }
    for (name, spec) in classes {
        let body = seed_model_class_body(spec);
        if body["candidates"].as_array().map(|a| a.is_empty()).unwrap_or(true) {
            ui::warned(&format!("skipped model class {name}: no candidates"));
            continue;
        }
        if dry_run {
            println!("{}", ui::status_line(Glyph::Step, &format!("would declare class {name}: {body}")));
            continue;
        }
        match crate::http::put_json_try(g, &format!("/api/cluster/model-classes/{}", super::urlencode(name)), &body, true, 15) {
            Ok(_) => {
                ui::done(&format!("{name}: {} candidate(s) declared", body["candidates"].as_array().map(|a| a.len()).unwrap_or(0)));
                applied += 1;
            }
            Err(e) => {
                println!("{}", ui::status_line(Glyph::Err, &format!("{name}: class failed ({e})")));
                failed += 1;
            }
        }
    }
    if !dry_run && !g.json {
        if failed == 0 {
            ui::close_done(&format!("{applied} change(s) applied"));
        } else {
            ui::close_failed(&format!("{applied} applied, {failed} failed"), Some("noo cluster desired <node>"));
        }
        println!("{}", ui::note("node-agents reconcile within 5 min"));
        ui::guide(&[("noo cluster status", "shows the nodes picking up the new placements")]);
    }
    if g.json {
        println!(
            "{}",
            serde_json::json!({"status": "ok", "action": if dry_run { "seed-dry-run" } else { "seed" }, "applied": applied, "failed": failed})
        );
    }
    Ok(0)
}

/// One RUNNING cell: `backend:model`, `backend*:model` when the backend is
/// native (found, not managed), and the bare backend when the agent reported
/// no model name (an older agent, or a backend that serves none).
fn running_cell(backend: &str, model: Option<&str>, native: bool) -> String {
    let name = if native { format!("{backend}*") } else { backend.to_string() };
    match model.map(str::trim).filter(|m| !m.is_empty()) {
        Some(m) => format!("{name}:{m}"),
        None => name,
    }
}

/// The harness kinds a `--kind` may name: config/harness-kinds.json, the
/// table the gateway and the node agent are built with too
/// (`crate::harness_kinds`).
fn harness_kind_names() -> Vec<String> {
    crate::harness_kinds::names()
}

#[cfg(test)]
mod harness_kind_tests {
    use super::*;

    #[test]
    fn the_kinds_come_from_the_shipped_table() {
        let kinds = harness_kind_names();
        assert_eq!(kinds.first().map(String::as_str), Some("noo"), "{kinds:?}");
        assert!(kinds.iter().any(|k| k == "codex"), "{kinds:?}");
    }

    #[test]
    fn the_place_usage_line_names_every_kind() {
        let (usage, _) = crate::usage::lookup(&["cluster", "place"]).expect("cluster place usage");
        let want = format!("[--kind {}]", harness_kind_names().join("|"));
        assert!(usage.contains(&want), "usage {usage:?} must carry {want:?}");
    }
}

#[cfg(test)]
mod seed_tests {
    use super::*;

    #[test]
    fn node_body_maps_ip_and_drops_nulls() {
        let cfg = serde_json::json!({
            "ip": "10.0.0.5", "ssh_user": "youruser", "tier": 1,
            "data_root": null, "gpu_model": "RTX 3080", "vram_gb": 10.0,
        });
        let body = seed_node_body(&cfg);
        assert_eq!(body["ip_address"].as_str(), Some("10.0.0.5"));
        assert_eq!(body["ssh_user"].as_str(), Some("youruser"));
        assert_eq!(body["tier"].as_i64(), Some(1));
        assert!(body.get("data_root").is_none(), "null values must be dropped");
        assert!(body.get("ip").is_none(), "seed key `ip` maps to `ip_address`");
    }

    #[test]
    fn placement_body_defaults_and_optionals() {
        // Minimal entry: model rides through (even null), tls coerces false,
        // state defaults running; port/image/env omitted.
        let p = serde_json::json!({"node": "n1", "backend": "vllm"});
        let body = seed_placement_body(&p);
        assert!(body["model"].is_null());
        assert_eq!(body["tls"].as_bool(), Some(false));
        assert_eq!(body["desired_state"].as_str(), Some("running"));
        assert!(body.get("port").is_none() && body.get("image").is_none() && body.get("env").is_none());

        // Full entry: everything mapped, `state` renamed to `desired_state`.
        let p = serde_json::json!({
            "node": "n1", "backend": "vllm", "model": "org/M", "port": 8000,
            "tls": true, "image": "img:1", "env": {"A": "1"}, "state": "stopped",
        });
        let body = seed_placement_body(&p);
        assert_eq!(body["model"].as_str(), Some("org/M"));
        assert_eq!(body["port"].as_i64(), Some(8000));
        assert_eq!(body["tls"].as_bool(), Some(true));
        assert_eq!(body["image"].as_str(), Some("img:1"));
        assert_eq!(body["env"]["A"].as_str(), Some("1"));
        assert_eq!(body["desired_state"].as_str(), Some("stopped"));
    }

    #[test]
    fn export_shapes_match_python() {
        let n = serde_json::json!({"ip_address": "10.0.0.5", "ssh_user": null, "tier": 2,
                                   "data_root": "/data", "models_dir": null});
        let y = seed_export_node(&n);
        assert_eq!(y["ip"].as_str(), Some("10.0.0.5"));
        assert_eq!(y["tier"].as_i64(), Some(2));
        assert!(y.get("ssh_user").is_none() && y.get("models_dir").is_none());

        let p = serde_json::json!({"backend": "ollama", "model": "qwen3:8b", "port": 11434,
                                   "tls": false, "image": null, "env": {}, "desired_state": "running"});
        let y = seed_export_placement("n1", &p);
        assert_eq!(y["node"].as_str(), Some("n1"));
        assert_eq!(y["backend"].as_str(), Some("ollama"));
        assert_eq!(y["state"].as_str(), Some("running"));
        assert!(y.get("tls").is_none(), "falsy tls omitted (Python `or None`)");
        assert!(y.get("env").is_none(), "empty env omitted (Python `or None`)");
    }

    #[test]
    fn assign_priority_words_map_to_the_schedulers_scale() {
        // Higher runs sooner (the queue is scored `-priority`), so `high`
        // must be ABOVE the route's default of 5 and `low` below it — a
        // mapping that inverted these would quietly deprioritise the urgent
        // work while still reporting success.
        assert_eq!(assign_priority("low"), Some(3));
        assert_eq!(assign_priority("medium"), Some(5));
        assert_eq!(assign_priority("normal"), Some(5));
        assert_eq!(assign_priority("high"), Some(8));
        assert_eq!(assign_priority("7"), Some(7), "a bare number passes through");
        // Unknown words are rejected rather than silently defaulted: a typo
        // like `--priority hihg` must not run at normal priority pretending
        // it was honoured.
        assert_eq!(assign_priority("urgent"), None);
        assert_eq!(assign_priority(""), None);
    }
}

#[cfg(test)]
mod running_cell_tests {
    use super::running_cell;

    /// A seed-file `model_classes` entry becomes the same PUT body
    /// `cluster class set` sends, and a declared class exports back.
    #[test]
    fn seed_model_classes_round_trip() {
        let spec = serde_json::json!({
            "aliases": ["gemma4:12b-any"],
            "candidates": [
                {"node": "host3", "backend": "vllm"},
                {"node": "host6", "backend": "ollama", "model": "gemma4:12b"},
                {"node": "host8", "backend": "ollama", "degraded": true},
            ],
        });
        let body = super::seed_model_class_body(&spec);
        let c = body["candidates"].as_array().unwrap();
        assert_eq!(c.len(), 3);
        assert!(c[0].get("model").is_none() && c[0].get("degraded").is_none());
        assert_eq!(c[1]["model"], "gemma4:12b");
        assert_eq!(c[2]["degraded"], true);
        assert_eq!(body["aliases"][0], "gemma4:12b-any");

        let live = serde_json::json!({
            "classes": [
                {"name": "chat-default", "declared": true, "candidates": [
                    {"node_id": "host3", "backend": "vllm", "model": "HF", "declared_model": null, "degraded": false},
                    {"node_id": "host6", "backend": "ollama", "model": "gemma4:12b", "declared_model": "gemma4:12b", "degraded": false},
                    {"node_id": "host8", "backend": "ollama", "model": "gemma4:e2b-it-qat", "declared_model": null, "degraded": true},
                ]},
                {"name": "HF", "declared": false, "candidates": [{"node_id": "host3", "backend": "vllm", "model": "HF"}]},
            ],
            "aliases": [
                {"alias": "default", "class": "chat-default", "builtin": true},
                {"alias": "gemma4:12b-any", "class": "chat-default", "builtin": false},
            ],
        });
        let out = super::seed_export_model_classes(&live);
        assert_eq!(out.len(), 1, "derived classes are not exported: {out:?}");
        let text = serde_yaml::to_string(&serde_yaml::Value::Mapping(out)).unwrap();
        assert!(text.contains("chat-default:") && text.contains("gemma4:12b-any") && text.contains("degraded: true"), "{text}");
        assert!(text.contains("model: gemma4:12b"), "a declared model is exported: {text}");
        assert!(!text.contains("HF") && !text.contains("e2b"), "a resolved placement model is NOT restated: {text}");
        assert!(!text.contains("default\n") || !text.contains("- default"), "built-in aliases are not exported: {text}");
    }

    #[test]
    fn running_cell_shows_the_model_beside_the_backend() {
        assert_eq!(running_cell("ollama", Some("harrier"), false), "ollama:harrier");
        assert_eq!(running_cell("ollama", Some("llama3.2:3b"), true), "ollama*:llama3.2:3b");
        assert_eq!(running_cell("vllm", None, false), "vllm");
        assert_eq!(running_cell("vllm", Some("  "), false), "vllm");
    }
}

#[cfg(test)]
mod model_presence_tests {
    use super::*;
    use serde_json::json;

    /// host9, 2026-10-03: container up, model absent.
    #[test]
    fn actual_reads_model_missing_when_the_node_reports_the_model_absent() {
        let n = json!({"id": "host9", "running_backends": {"ollama": "harrier"},
            "model_presence": {"ollama": {"model": "harrier", "role": "embed", "present": false}}});
        let cell = actual_cell(&n, "ollama", "-");
        assert!(cell.contains("model missing"), "{cell}");
        assert!(!cell.to_lowercase().contains("running"), "{cell}");
    }

    #[test]
    fn an_old_agent_or_a_held_model_still_reads_running() {
        let old = json!({"running_backends": {"ollama": "harrier"}});
        assert!(actual_cell(&old, "ollama", "-").to_lowercase().contains("running"));
        let held = json!({"running_backends": {"ollama": "harrier"},
            "model_presence": {"ollama": {"model": "harrier", "present": true}}});
        assert!(actual_cell(&held, "ollama", "-").to_lowercase().contains("running"));
        // Absent from running_backends stays "not running", whatever the report says.
        let down = json!({"running_backends": {}, "model_presence": {"ollama": {"present": false}}});
        assert!(actual_cell(&down, "ollama", "-").to_lowercase().contains("not running"));
    }
}

#[cfg(test)]
mod authenticated_fleet_reads_tests {
    /// Every read of `/api/cluster/nodes` in this file must send a
    /// credential. One of the nine shipped with `with_auth: false`, and
    /// the 401 it earned was rendered as "your token is expired or
    /// revoked" — sending the operator to `noo auth login` twice for a
    /// problem no login could fix (2026-09-21). An unauthenticated read
    /// of a fleet endpoint has no legitimate caller here, so the guard is
    /// a flat ban rather than a count.
    #[test]
    fn no_fleet_read_goes_out_without_a_credential() {
        let src = include_str!("cluster.rs");
        let calls = src.matches("\"/api/cluster/nodes\"").count();
        assert!(calls >= 8, "expected the fleet endpoint to be read here, found {calls}");
        let unauthenticated: Vec<&str> = src
            .lines()
            .filter(|l| l.contains("\"/api/cluster/nodes\", false"))
            .map(|l| l.trim())
            .collect();
        assert!(
            unauthenticated.is_empty(),
            "these read the fleet without a credential and will 401: {unauthenticated:#?}"
        );
    }
}

#[cfg(test)]
mod forget_args_tests {
    use super::parse_forget_args;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn forget_yes_flag_is_parsed_in_either_position() {
        assert_eq!(parse_forget_args(&a(&["gpu-1", "-y"])), Some(("gpu-1".into(), false, true)));
        assert_eq!(parse_forget_args(&a(&["--yes", "gpu-1", "--purge-tailscale"])), Some(("gpu-1".into(), true, true)));
    }

    #[test]
    fn forget_takes_a_node_and_an_optional_tailnet_purge_in_either_order() {
        assert_eq!(parse_forget_args(&a(&["gpu-1"])), Some(("gpu-1".into(), false, false)));
        assert_eq!(parse_forget_args(&a(&["gpu-1", "--purge-tailscale"])), Some(("gpu-1".into(), true, false)));
        assert_eq!(parse_forget_args(&a(&["--purge-tailscale", "gpu-1"])), Some(("gpu-1".into(), true, false)));
    }

    #[test]
    fn forget_refuses_what_it_does_not_understand() {
        assert_eq!(parse_forget_args(&a(&[])), None, "no node");
        assert_eq!(parse_forget_args(&a(&["--purge-tailscale"])), None, "flag without a node");
        assert_eq!(parse_forget_args(&a(&["gpu-1", "gpu-2"])), None, "two nodes");
        assert_eq!(parse_forget_args(&a(&["gpu-1", "--purge-data"])), None, "a teardown flag is not a forget flag");
    }
}

#[cfg(test)]
mod proposals_args_tests {
    use super::{parse_proposals_args, ProposalsArgs};

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn proposals_takes_an_optional_status_and_limit() {
        assert_eq!(parse_proposals_args(&a(&[])).unwrap(), ProposalsArgs { status: None, limit: None });
        assert_eq!(
            parse_proposals_args(&a(&["--status", "pending", "--limit", "5"])).unwrap(),
            ProposalsArgs { status: Some("pending".into()), limit: Some(5) }
        );
        assert_eq!(parse_proposals_args(&a(&["-n", "3"])).unwrap().limit, Some(3));
    }

    #[test]
    fn proposals_refuses_what_it_does_not_understand() {
        assert!(parse_proposals_args(&a(&["pending"])).is_err(), "a bare positional");
        assert!(parse_proposals_args(&a(&["--status"])).is_err(), "a flag with no value");
        assert!(parse_proposals_args(&a(&["--limit", "many"])).is_err(), "a non-numeric limit");
    }
}

/// What `noo cluster maintenance` was asked to do.
#[derive(Debug, PartialEq)]
enum MaintenanceArgs {
    List,
    On { node: String, reason: String, until_secs: Option<i64> },
    Off { node: String },
}

/// `30s`, `45m`, `4h`, `2d` as seconds. Nothing else: a bare number would
/// not say its unit.
fn parse_until(s: &str) -> Option<i64> {
    let (num, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: i64 = num.parse().ok().filter(|n| *n > 0)?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    n.checked_mul(mult)
}

fn parse_maintenance_args(args: &[String]) -> Result<MaintenanceArgs, ()> {
    match args {
        [l] if l == "list" => Ok(MaintenanceArgs::List),
        [node, off] if off == "off" && !node.starts_with('-') => {
            Ok(MaintenanceArgs::Off { node: node.clone() })
        }
        [node, on, rest @ ..] if on == "on" && !node.starts_with('-') => {
            let mut reason: Option<String> = None;
            let mut until_secs: Option<i64> = None;
            let mut iter = rest.iter();
            while let Some(tok) = iter.next() {
                match tok.as_str() {
                    "--reason" => reason = Some(iter.next().ok_or(())?.clone()),
                    "--until" => until_secs = Some(parse_until(iter.next().ok_or(())?).ok_or(())?),
                    _ => return Err(()),
                }
            }
            let reason = reason.filter(|r| !r.trim().is_empty()).ok_or(())?;
            Ok(MaintenanceArgs::On { node: node.clone(), reason, until_secs })
        }
        _ => Err(()),
    }
}

/// `noo cluster maintenance <node> on --reason <text> [--until <duration>]`,
/// `<node> off`, or `list`. Mutes (and unmutes) a known-down node's operator
/// alerts at the gateway; operator-only.
pub fn cluster_maintenance(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let parsed = parse_maintenance_args(args).map_err(|_| Unhandled)?;
    match parsed {
        MaintenanceArgs::On { node, reason, until_secs } => {
            let resp = put_json(
                g,
                &format!("/api/cluster/nodes/{}/maintenance", super::urlencode(&node)),
                &serde_json::json!({"reason": reason, "until_secs": until_secs}),
                true,
                10,
            );
            if g.json {
                println!("{resp}");
                return Ok(0);
            }
            match until_secs {
                Some(_) => ui::done(&format!("{node} is in maintenance; its alerts are muted until the window ends")),
                None => ui::done(&format!("{node} is in maintenance; its alerts are muted until you turn it off")),
            }
            ui::guide(&[("noo cluster maintenance list", "shows every node in maintenance"), ("noo cluster maintenance <node> off", "restores its alerts")]);
            Ok(0)
        }
        MaintenanceArgs::Off { node } => {
            let resp = delete_json(
                g,
                &format!("/api/cluster/nodes/{}/maintenance", super::urlencode(&node)),
                true,
                10,
            );
            if g.json {
                println!("{resp}");
                return Ok(0);
            }
            if resp["was_on"].as_bool().unwrap_or(false) {
                ui::done(&format!("{node} is out of maintenance; its alerts are delivered again"));
            } else {
                ui::done(&format!("{node} was not in maintenance"));
            }
            Ok(0)
        }
        MaintenanceArgs::List => {
            let body = get_json(g, "/api/cluster/maintenance", true, 10);
            if g.json {
                println!("{body}");
                return Ok(0);
            }
            let empty = Vec::new();
            let entries = body["maintenance"].as_array().unwrap_or(&empty);
            println!("{}", ui::header("maintenance", Some("nodes whose alerts are muted")));
            if entries.is_empty() {
                println!("{}", ui::muted("no node is in maintenance"));
                return Ok(0);
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let rows: Vec<Vec<String>> = entries
                .iter()
                .map(|m| {
                    let until = match m["until"].as_i64() {
                        Some(u) => format!("{} left", fmt_span(u - now)),
                        None => "until turned off".to_string(),
                    };
                    vec![
                        m["node"].as_str().unwrap_or("?").to_string(),
                        m["reason"].as_str().unwrap_or("").to_string(),
                        until,
                        m["by"].as_str().unwrap_or("").to_string(),
                    ]
                })
                .collect();
            print!(
                "{}",
                ui::table(&[Col::left("node"), Col::left("reason"), Col::left("window"), Col::left("set by")], &rows)
            );
            Ok(0)
        }
    }
}

fn fmt_span(secs: i64) -> String {
    let s = secs.max(0);
    if s >= 86_400 {
        format!("{}d {}h", s / 86_400, (s % 86_400) / 3600)
    } else if s >= 3600 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}m", s / 60)
    }
}

#[cfg(test)]
mod maintenance_args_tests {
    use super::{parse_maintenance_args, parse_until, MaintenanceArgs};

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn on_needs_a_reason_and_takes_an_optional_window() {
        assert_eq!(
            parse_maintenance_args(&a(&["alpha", "on", "--reason", "disk swap", "--until", "4h"])),
            Ok(MaintenanceArgs::On { node: "alpha".into(), reason: "disk swap".into(), until_secs: Some(14_400) })
        );
        assert_eq!(
            parse_maintenance_args(&a(&["alpha", "on", "--reason", "moving"])),
            Ok(MaintenanceArgs::On { node: "alpha".into(), reason: "moving".into(), until_secs: None })
        );
        assert!(parse_maintenance_args(&a(&["alpha", "on"])).is_err(), "no reason");
        assert!(parse_maintenance_args(&a(&["alpha", "on", "--reason", " "])).is_err(), "blank reason");
        assert!(parse_maintenance_args(&a(&["alpha", "on", "--reason", "x", "--until", "4"])).is_err(), "unitless window");
        assert!(parse_maintenance_args(&a(&["alpha", "on", "--reason", "x", "--bogus"])).is_err());
    }

    #[test]
    fn off_and_list_take_no_extras() {
        assert_eq!(parse_maintenance_args(&a(&["alpha", "off"])), Ok(MaintenanceArgs::Off { node: "alpha".into() }));
        assert_eq!(parse_maintenance_args(&a(&["list"])), Ok(MaintenanceArgs::List));
        assert!(parse_maintenance_args(&a(&["alpha"])).is_err());
        assert!(parse_maintenance_args(&a(&["list", "alpha"])).is_err());
        assert!(parse_maintenance_args(&a(&[])).is_err());
    }

    #[test]
    fn windows_need_a_unit() {
        assert_eq!(parse_until("90s"), Some(90));
        assert_eq!(parse_until("45m"), Some(2700));
        assert_eq!(parse_until("2d"), Some(172_800));
        assert_eq!(parse_until("0h"), None);
        assert_eq!(parse_until("h"), None);
        assert_eq!(parse_until("5"), None);
        assert_eq!(parse_until(""), None);
    }
}

#[cfg(test)]
mod cluster_fix_tests {
    use super::*;

    fn g() -> Globals {
        Globals { json: false, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: false }
    }

    #[test]
    fn clear_cooldowns_refuses_a_node_argument_instead_of_ignoring_it() {
        // Returns before any network call: the gateway clears every node.
        assert!(cluster_clear_cooldowns(&g(), &["gpu-1".to_string()]).is_err());
    }

    #[test]
    fn ssh_user_is_a_named_retired_flag() {
        assert!(retired_set_config_flag("--ssh-user").unwrap().contains("retired"));
        assert!(retired_set_config_flag("--ip").is_none());
    }
}

#[cfg(test)]
mod manifest_warm_tests {
    use super::{classify_manifest_answer as c, path_escape, ManifestWarm as W};

    #[test]
    fn the_gateway_answers_map_to_what_sync_does_next() {
        let sha = "AB".repeat(32);
        assert_eq!(c(200, &format!(r#"{{"sha256":"{sha}"}}"#)), W::Ready("ab".repeat(32)));
        assert!(matches!(c(200, "{}"), W::Failed(_)), "a 200 without a digest is not ready");
        assert_eq!(c(202, r#"{"status":"hashing","retry_after_secs":5}"#), W::Hashing(5));
        assert_eq!(c(202, "{}"), W::Hashing(5), "a bare 202 still means retry");
        assert_eq!(c(202, r#"{"retry_after_secs":3600}"#), W::Hashing(15), "capped");
        assert_eq!(c(404, r#"{"error":"no gguf artifact"}"#), W::Missing);
        assert_eq!(c(500, r#"{"error":"hashing x: read: EIO"}"#), W::Failed("HTTP 500: hashing x: read: EIO".into()));
    }

    #[test]
    fn filenames_are_path_escaped() {
        assert_eq!(path_escape("gemma-4-E2B_q4_0-it.gguf"), "gemma-4-E2B_q4_0-it.gguf");
        assert_eq!(path_escape("a b+c.gguf"), "a%20b%2Bc.gguf");
        assert_eq!(path_escape("../x"), "..%2Fx");
    }
}
