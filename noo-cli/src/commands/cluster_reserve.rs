// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster reserve|reservations|release` — a feature that must
//! continuously consume a piece of the mesh (voice while voice is on; an
//! image or video worker with its model loaded) reserves a GPU; that
//! capacity is not routable to the pool until released. The workload is
//! what an add-on's verified bundle declares (`<addon>/<workload>`); the
//! mesh picks the node (any live node with enough free GPU memory) unless
//! `--node` pins one. Taking a reservation drains the pool's work on that
//! GPU first (nothing in flight is cut), pauses the pool's backends, starts
//! the workload and waits for it to run; releasing runs the workload's own
//! drain, stops it and hands the GPU back at once. Operator-only, audited.

use serde_json::Value;

use crate::args::{ArgError, Args};
use crate::http::{get_json, request_status};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col};
use crate::{Globals, Unhandled};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReserveArgs {
    pub workload: String,
    pub node: Option<String>,
    pub hand_over: Option<String>,
    pub timeout: Option<u64>,
}

pub(crate) fn parse_reserve(args: &[String]) -> Result<ReserveArgs, ArgError> {
    parse_reserve_with(&mut Args::new(args))
}

pub(crate) fn parse_reserve_with(a: &mut Args) -> Result<ReserveArgs, ArgError> {
    let node = a.value(&["--node"])?.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let hand_over = a.value(&["--hand-over"])?.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let timeout = a.number::<u64>(&["--timeout"])?;
    let workload = a.one("<addon>/<workload>")?;
    if !workload.contains('/') {
        return Err(ArgError::new(format!("`{workload}` is not <addon>/<workload>")));
    }
    Ok(ReserveArgs { workload, node, hand_over, timeout })
}

pub(crate) fn parse_release(args: &[String]) -> Result<(String, bool), ()> {
    let [id, rest @ ..] = args else { return Err(()) };
    if id.starts_with('-') {
        return Err(());
    }
    match rest {
        [] => Ok((id.clone(), false)),
        [f] if f == "--force" => Ok((id.clone(), true)),
        _ => Err(()),
    }
}

/// `noo cluster reserve <addon>/<workload> [--node <node>] [--hand-over <reservation-id>] [--timeout <secs>]`
pub fn cluster_reserve(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let a = parse_reserve(args)?;
    let timeout = a.timeout.unwrap_or(120).clamp(1, 900);
    let mut body = serde_json::json!({"workload": a.workload, "timeout_secs": timeout});
    if let Some(n) = &a.node {
        body["node"] = Value::String(n.clone());
    }
    if let Some(h) = &a.hand_over {
        body["hand_over"] = Value::String(h.clone());
    }
    if !g.json {
        println!("{}", ui::muted(&format!(
            "{}: reserving a GPU{} — the pool's work there finishes first (up to {timeout} s), then the workload starts",
            a.workload,
            a.node.as_deref().map(|n| format!(" on {n}")).unwrap_or_default()
        )));
    }
    // drain + hold + start + ready wait: generous, the gateway bounds each step.
    let resp = match request_status(g, "POST", "/api/cluster/reservations", Some(&body), true, timeout + 400) {
        Ok(v) => v,
        Err((status, text)) => refused(g, "reserve", &a.workload, status, &text),
    };
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let id = resp["id"].as_str().unwrap_or("?");
    let node = resp["node"].as_str().unwrap_or("?");
    let paused = resp["paused_backends"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    match resp["status"].as_str().unwrap_or("") {
        "reserved" => {
            ui::done(&format!("{}: reserved on {node} — {} running; the pool's {} paused",
                a.workload,
                resp["worker"]["container"].as_str().unwrap_or("the workload"),
                if paused.is_empty() { "GPU backends".to_string() } else { paused }));
        }
        other => {
            ui::warned(&format!("{}: reservation {id} on {node} is {other} — {}", a.workload, resp["detail"].as_str().unwrap_or("")));
        }
    }
    println!("{}", ui::muted(&format!("reservation {id} (generation {})", resp["lease"]["generation"].as_u64().unwrap_or(0))));
    let release = format!("noo cluster release {id}");
    ui::guide(&[
        (release.as_str(), "drains the workload, stops it and returns the GPU to the pool"),
        ("noo cluster reservations", "who holds what, where"),
    ]);
    Ok(0)
}

/// `noo cluster reservations`
pub fn cluster_reservations(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/cluster/reservations", true, 15);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let list = body["reservations"].as_array().unwrap_or(&empty);
    println!("{}", ui::header("reservations", Some("GPU capacity held out of the pool")));
    if list.is_empty() {
        println!("{}", ui::muted("none — every GPU serves the pool"));
        ui::guide(&[("noo cluster workloads", "what the installed add-ons can reserve")]);
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|r| {
            let workload = r["workload"].as_str().filter(|w| !w.is_empty()).map(str::to_string).unwrap_or_else(|| ui::muted("gpu hold"));
            let state = match r["state"].as_str().unwrap_or("") {
                "held" => ui::good("held"),
                "draining" => ui::muted("draining"),
                other => ui::bad(other),
            };
            vec![
                r["id"].as_str().unwrap_or("?").to_string(),
                workload,
                r["holder"].as_str().unwrap_or("?").to_string(),
                r["node"].as_str().unwrap_or("?").to_string(),
                state,
                r["since"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();
    println!("{}", ui::table(&[Col::left("reservation"), Col::left("workload"), Col::left("holder"), Col::left("node"), Col::left("state"), Col::left("since")], &rows));
    ui::guide(&[("noo cluster release <reservation-id>", "returns that GPU to the pool")]);
    Ok(0)
}

/// `noo cluster workloads`
pub fn cluster_workloads(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/cluster/workloads", true, 15);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let list = body["workloads"].as_array().unwrap_or(&empty);
    println!("{}", ui::header("workloads", Some("what the installed add-ons declare")));
    if list.is_empty() {
        println!("{}", ui::muted("none — no registered add-on declares a workload"));
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|w| {
            vec![
                w["workload"].as_str().unwrap_or("?").to_string(),
                w["container"].as_str().unwrap_or("?").to_string(),
                if w["gpu"].as_bool().unwrap_or(false) { format!("{} MB", w["need_mb"].as_u64().unwrap_or(0)) } else { "cpu".to_string() },
                w["drain"]["route"].as_str().map(|r| format!("{r} ({} s)", w["drain"]["timeout_secs"].as_u64().unwrap_or(0))).unwrap_or_else(|| ui::muted("none")),
            ]
        })
        .collect();
    println!("{}", ui::table(&[Col::left("workload"), Col::left("container"), Col::left("gpu"), Col::left("drain")], &rows));
    ui::guide(&[("noo cluster reserve <addon>/<workload>", "reserves a GPU for it")]);
    Ok(0)
}

/// `noo cluster release <reservation-id> [--force]`
pub fn cluster_release(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let Ok((id, force)) = parse_release(args) else { return Err(Unhandled) };
    let body = serde_json::json!({"force": force});
    let resp = match request_status(g, "POST", &format!("/api/cluster/reservations/{}/release", super::urlencode(&id)), Some(&body), true, 900) {
        Ok(v) => v,
        Err((status, text)) => refused(g, "release", &id, status, &text),
    };
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let node = resp["node"].as_str().unwrap_or("?");
    let workload = resp["workload"].as_str().filter(|w| !w.is_empty()).unwrap_or("the hold");
    ui::done(&format!("{workload}: released{} — {node}'s GPU backends are resuming", if force { " (force)" } else { "" }));
    Ok(0)
}

/// Render a refusal: the gateway's code and sentence, with the remedy.
fn refused(g: &Globals, op: &str, what: &str, status: u16, text: &str) -> ! {
    let msg = serde_json::from_str::<Value>(text).ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_else(|| text.trim().to_string());
    let (kind, hint) = refusal_hint(op, what, status, &msg);
    fail(g.json, ExitCode::RemoteError, kind, &format!("{what}: {op} refused — {msg}"), Some(&hint))
}

fn refusal_hint(op: &str, what: &str, status: u16, msg: &str) -> (&'static str, String) {
    if status == 404 && msg.contains("declares") {
        ("workload_unknown", "noo cluster workloads   # what the installed add-ons declare".to_string())
    } else if status == 404 {
        ("reservation_unknown", "noo cluster reservations".to_string())
    } else if msg.starts_with("not_owner") {
        ("reservation_not_owner", format!("noo cluster release {what} --force   # audited"))
    } else if msg.contains("can take") || msg.contains("no node") {
        ("no_node_fits", "noo cluster status   # which nodes report a GPU and how much is free".to_string())
    } else if msg.starts_with("drain_timeout") || msg.contains("did not stop") || msg.contains("did not start") {
        ("reservation_needs_attention", "noo cluster reservations   # the current holder stays; nothing was cut".to_string())
    } else if msg.starts_with("held_by_other") || msg.starts_with("transition_in_progress") {
        ("gpu_busy", "noo cluster reservations".to_string())
    } else if op == "reserve" {
        ("reserve_refused", "noo cluster reservations".to_string())
    } else {
        ("release_refused", "noo cluster reservations".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_reserve_and_release() {
        assert_eq!(parse_reserve(&a(&["pai-voice/voice-worker"])),
            Ok(ReserveArgs { workload: "pai-voice/voice-worker".into(), node: None, hand_over: None, timeout: None }));
        assert_eq!(parse_reserve(&a(&["pai-voice/voice-worker", "--node", "awolf", "--hand-over", "res-1", "--timeout", "300"])),
            Ok(ReserveArgs { workload: "pai-voice/voice-worker".into(), node: Some("awolf".into()), hand_over: Some("res-1".into()), timeout: Some(300) }));
        assert!(parse_reserve(&a(&["voice-worker"])).is_err(), "addon/workload");
        assert!(parse_reserve(&a(&[])).is_err());
        assert!(parse_reserve(&a(&["a/b", "--node"])).is_err());
        assert!(parse_reserve(&a(&["a/b", "--bogus"])).is_err());
        assert_eq!(parse_release(&a(&["res-1"])), Ok(("res-1".into(), false)));
        assert_eq!(parse_release(&a(&["res-1", "--force"])), Ok(("res-1".into(), true)));
        assert!(parse_release(&a(&["res-1", "x"])).is_err());
        assert!(parse_release(&a(&["--force"])).is_err());
    }

    #[test]
    fn refusals_name_a_remedy() {
        assert_eq!(refusal_hint("reserve", "pai-voice/x", 404, "no verified add-on bundle declares workload pai-voice/x").0, "workload_unknown");
        assert_eq!(refusal_hint("release", "res-1", 404, "no reservation res-1").0, "reservation_unknown");
        let (k, h) = refusal_hint("release", "res-1", 409, "not_owner: reservation res-1 is held by a");
        assert_eq!(k, "reservation_not_owner");
        assert!(h.starts_with("noo cluster release res-1 --force"));
        assert_eq!(refusal_hint("reserve", "a/b", 409, "no node can take a/b: awolf: GPU held by x").0, "no_node_fits");
        assert_eq!(refusal_hint("reserve", "a/b", 409, "drain_timeout: still in flight").0, "reservation_needs_attention");
        assert_eq!(refusal_hint("release", "r", 409, "a/b did not stop on awolf: drain route refused").0, "reservation_needs_attention");
    }
}
