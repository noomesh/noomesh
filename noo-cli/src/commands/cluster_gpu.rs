// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster gpu hold|release <node>` — the operator's hand on a shared
//! GPU node (node agent `internal/gpuyield`).
//!
//! The agent yields its GPU backends on its own when foreign work takes the
//! GPU, but whoever starts first holds the GPU: a stack that refuses to start
//! while the GPU is occupied (pai-voice) can never get it from a running
//! vLLM. `hold` drains the node's GPU backends (nothing new is routed or
//! admitted; what runs finishes), pauses them and keeps them paused;
//! `release` hands the node back to the automatic policy, which resumes them
//! once the GPU has stayed free. Operator-only and audited at the gateway.
//!
//! A hold is an owned lease: it carries an operation id and is given the
//! node's next generation; `release` quotes both (compare-and-set) so a
//! stale retry can never end somebody else's hold. A bare `release` is an
//! operator force-release, audited as such.

use serde_json::Value;

use crate::http::request_status;
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GpuArgs {
    Hold {
        node: String,
        reason: Option<String>,
        operation: Option<String>,
        immediate: bool,
        timeout: Option<u64>,
        force: bool,
    },
    Release {
        node: String,
        operation: Option<String>,
        generation: Option<u64>,
        force: bool,
        resume_now: bool,
    },
}

pub(crate) fn parse_gpu_hold(args: &[String]) -> Result<GpuArgs, ()> {
    let [node, rest @ ..] = args else { return Err(()) };
    if node.starts_with('-') {
        return Err(());
    }
    let (mut reason, mut operation, mut immediate, mut timeout, mut force) = (None, None, false, None, false);
    let mut it = rest.iter();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "--reason" => reason = Some(it.next().ok_or(())?.trim().to_string()).filter(|r| !r.is_empty()),
            "--operation" => operation = Some(it.next().ok_or(())?.trim().to_string()).filter(|r| !r.is_empty()),
            "--timeout" => timeout = Some(it.next().ok_or(())?.trim().parse::<u64>().map_err(|_| ())?),
            "--immediate" => immediate = true,
            "--force" => force = true,
            _ => return Err(()),
        }
    }
    Ok(GpuArgs::Hold { node: node.clone(), reason, operation, immediate, timeout, force })
}

pub(crate) fn parse_gpu_release(args: &[String]) -> Result<GpuArgs, ()> {
    let [node, rest @ ..] = args else { return Err(()) };
    if node.starts_with('-') {
        return Err(());
    }
    let (mut operation, mut generation, mut force, mut resume_now) = (None, None, false, false);
    let mut it = rest.iter();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "--operation" => operation = Some(it.next().ok_or(())?.trim().to_string()).filter(|r| !r.is_empty()),
            "--generation" => generation = Some(it.next().ok_or(())?.trim().parse::<u64>().map_err(|_| ())?),
            "--force" => force = true,
            "--now" => resume_now = true,
            _ => return Err(()),
        }
    }
    // The ids come as a pair: one without the other releases nothing.
    if operation.is_some() != generation.is_some() {
        return Err(());
    }
    Ok(GpuArgs::Release { node: node.clone(), operation, generation, force, resume_now })
}

/// A fresh operation id for a hold the operator did not name: a random
/// UUID (v4 layout) from the OS, so two holds never collide.
fn new_operation_id() -> String {
    use std::io::Read;
    let mut b = [0u8; 16];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_err() {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        b.copy_from_slice(&t.to_le_bytes());
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// `noo cluster gpu hold <node> [--reason <text>] [--operation <id>] [--timeout <s>] [--immediate] [--force]`
pub fn cluster_gpu_hold(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let Ok(GpuArgs::Hold { node, reason, operation, immediate, timeout, force }) = parse_gpu_hold(args) else {
        return Err(Unhandled);
    };
    let operation = operation.unwrap_or_else(new_operation_id);
    let timeout = timeout.unwrap_or(120).clamp(1, 900);
    let body = serde_json::json!({
        "reason": reason.clone().unwrap_or_default(),
        "operation_id": operation,
        "mode": if immediate { "immediate" } else { "drain" },
        "timeout_secs": timeout,
        "force": force,
    });
    if !g.json && !immediate {
        println!("{}", ui::muted(&format!("{node}: draining its GPU backends (nothing new routed there; up to {timeout} s for what runs to finish)")));
    }
    let resp = match request_status(g, "POST", &format!("/api/cluster/nodes/{}/gpu/hold", super::urlencode(&node)), Some(&body), true, timeout + 90) {
        Ok(v) => v,
        Err((status, text)) => hold_refused(g, &node, "hold", status, &text),
    };
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let gc = &resp["gpu_contention"];
    let paused = paused_list(gc);
    let lease = &gc["lease"];
    let generation = lease["generation"].as_u64().unwrap_or(0);
    let op = lease["operation_id"].as_str().unwrap_or(&operation);
    ui::done(&format!("{node}: GPU held{} — {paused} paused; it stays paused until you release it",
        reason.map(|r| format!(" ({r})")).unwrap_or_default()));
    println!("{}", ui::muted(&format!("lease: operation {op}, generation {generation}{}",
        if immediate { " (immediate: requests in flight were cut)" } else { ", drained first" })));
    let release = format!("noo cluster gpu release {node} --operation {op} --generation {generation}");
    ui::guide(&[
        (release.as_str(), "returns the node to automatic sharing: its GPU backends resume once the GPU is free (add --now to resume at once)"),
        ("noo cluster verify <node>", "the `gpu` row shows the hold and its owner"),
    ]);
    Ok(0)
}

/// `noo cluster gpu release <node> [--operation <id> --generation <n>] [--force] [--now]`
pub fn cluster_gpu_release(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let Ok(GpuArgs::Release { node, operation, generation, force, resume_now }) = parse_gpu_release(args) else {
        return Err(Unhandled);
    };
    let mut body = serde_json::json!({"force": force || operation.is_none()});
    if let (Some(op), Some(generation)) = (&operation, generation) {
        body["operation_id"] = Value::String(op.clone());
        body["generation"] = Value::from(generation);
    }
    if resume_now {
        body["resume"] = Value::String("now".into());
    }
    let resp = match request_status(g, "POST", &format!("/api/cluster/nodes/{}/gpu/release", super::urlencode(&node)), Some(&body), true, 90) {
        Ok(v) => v,
        Err((status, text)) => hold_refused(g, &node, "release", status, &text),
    };
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let how = if operation.is_none() { " (force: whoever held it)" } else { "" };
    match resp["gpu_contention"]["state"].as_str() {
        Some("yielded") => ui::done(&format!(
            "{node}: hold released{how} — {} resume once the GPU has stayed free (NOO_GPU_RESUME_AFTER_S, default 120 s)",
            paused_list(&resp["gpu_contention"]))),
        Some("free") | Some("shared") if resume_now => ui::done(&format!("{node}: hold released{how} — GPU backends resuming now")),
        _ => ui::done(&format!("{node}: hold released{how}; nothing was paused")),
    }
    Ok(0)
}

/// Render the gateway's 409 for a hold or release: whose lease it is, what
/// still runs, or that another transition is in progress.
fn hold_refused(g: &Globals, node: &str, op: &str, status: u16, text: &str) -> ! {
    let msg = serde_json::from_str::<Value>(text).ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_else(|| text.trim().to_string());
    if status != 409 {
        fail(g.json, ExitCode::RemoteError, "remote_error", &format!("gateway returned {status} for the GPU {op} on {node}: {msg}"), None);
    }
    let (kind, hint) = refusal_hint(node, op, &msg);
    fail(g.json, ExitCode::RemoteError, kind, &format!("{node}: GPU {op} refused — {msg}"), Some(&hint))
}

/// The exit kind and the remedy for a 409's machine-readable code.
fn refusal_hint(node: &str, op: &str, msg: &str) -> (&'static str, String) {
    if msg.starts_with("held_by_other") {
        ("gpu_held_by_other", format!("noo cluster gpu {op} {node} --force   # take it over (audited); or quote the lease's --operation and --generation"))
    } else if msg.starts_with("drain_timeout") {
        ("gpu_drain_timeout", format!("noo cluster gpu hold {node} --timeout 600   # wait longer; --immediate cuts what runs (emergency)"))
    } else if msg.starts_with("transition_in_progress") || msg.contains("already in progress") {
        ("gpu_transition_in_progress", format!("noo cluster verify {node}   # wait for the running hold or release to finish"))
    } else if msg.starts_with("not_held") {
        ("gpu_not_held", format!("noo cluster verify {node}   # the gpu row shows the node's state"))
    } else {
        ("gpu_hold_refused", format!("noo cluster verify {node}"))
    }
}

fn paused_list(gc: &Value) -> String {
    let names: Vec<&str> = gc["paused_backends"].as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if names.is_empty() { "no GPU backend".to_string() } else { names.join(", ") }
}

/// Who holds it, for a status line: the lease's owner, else "operator".
pub(crate) fn lease_holder(gc: &Value) -> String {
    gc["lease"]["owner"].as_str().filter(|o| !o.is_empty()).unwrap_or("operator").to_string()
}

/// The `noo cluster status` note for a node whose GPU went to other work, or
/// None when there is nothing to say (free, shared, unreported).
pub(crate) fn gpu_status_note(n: &Value) -> Option<String> {
    let id = n["id"].as_str().unwrap_or("?");
    let gc = n.get("gpu_contention").filter(|v| v.is_object())?;
    let paused = paused_list(gc);
    let since = gc["since"].as_str().map(|s| format!(" since {s}")).unwrap_or_default();
    match gc["state"].as_str()? {
        "yielded" => Some(format!("{id}: GPU in use by other work — {paused} paused{since} (foreign {:.1} GB)",
            gc["foreign_mb"].as_f64().unwrap_or(0.0) / 1024.0)),
        "held" => Some(format!("{id}: GPU held by {}{} — {paused} paused{since}",
            lease_holder(gc),
            gc["reason"].as_str().filter(|r| !r.is_empty()).map(|r| format!(" ({r})")).unwrap_or_default())),
        "draining" => Some(format!("{id}: GPU hold by {} draining — waiting for requests in flight to finish{since}", lease_holder(gc))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_hold_and_release() {
        assert_eq!(parse_gpu_hold(&a(&["host3", "--reason", "voice"])),
            Ok(GpuArgs::Hold { node: "host3".into(), reason: Some("voice".into()), operation: None, immediate: false, timeout: None, force: false }));
        assert_eq!(parse_gpu_hold(&a(&["host3", "--operation", "op-1", "--timeout", "300", "--immediate", "--force"])),
            Ok(GpuArgs::Hold { node: "host3".into(), reason: None, operation: Some("op-1".into()), immediate: true, timeout: Some(300), force: true }));
        assert!(parse_gpu_hold(&a(&[])).is_err());
        assert!(parse_gpu_hold(&a(&["host3", "--reason"])).is_err());
        assert!(parse_gpu_hold(&a(&["host3", "--timeout", "soon"])).is_err());
        assert!(parse_gpu_hold(&a(&["host3", "--bogus"])).is_err());
        assert_eq!(parse_gpu_release(&a(&["host3"])),
            Ok(GpuArgs::Release { node: "host3".into(), operation: None, generation: None, force: false, resume_now: false }));
        assert_eq!(parse_gpu_release(&a(&["host3", "--operation", "op-1", "--generation", "4", "--now"])),
            Ok(GpuArgs::Release { node: "host3".into(), operation: Some("op-1".into()), generation: Some(4), force: false, resume_now: true }));
        assert!(parse_gpu_release(&a(&["host3", "--operation", "op-1"])).is_err(), "the ids come as a pair");
        assert!(parse_gpu_release(&a(&["host3", "--generation", "x"])).is_err());
        assert!(parse_gpu_release(&a(&["host3", "x"])).is_err());
        assert!(parse_gpu_release(&a(&["--x"])).is_err());
    }

    #[test]
    fn operation_ids_are_uuids_and_distinct() {
        let (x, y) = (new_operation_id(), new_operation_id());
        assert_ne!(x, y);
        assert_eq!(x.len(), 36);
        assert_eq!(x.as_bytes()[14], b'4', "{x}");
        assert!(x.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    }

    #[test]
    fn refusals_get_a_kind_and_a_remedy() {
        let (k, h) = refusal_hint("host3", "release", "held_by_other: held by a (operation op-1, generation 2)");
        assert_eq!(k, "gpu_held_by_other");
        assert!(h.starts_with("noo cluster gpu release host3 --force"), "{h}");
        let (k, h) = refusal_hint("host3", "hold", "drain_timeout: still in flight after 2m0s (vllm: 1)");
        assert_eq!(k, "gpu_drain_timeout");
        assert!(h.contains("--timeout 600") && h.contains("--immediate"), "{h}");
        assert_eq!(refusal_hint("host3", "hold", "transition_in_progress: ...").0, "gpu_transition_in_progress");
        assert_eq!(refusal_hint("host3", "hold", "a GPU hold or release on host3 is already in progress").0, "gpu_transition_in_progress");
        assert_eq!(refusal_hint("host3", "release", "not_held: the node's GPU is not held").0, "gpu_not_held");
    }

    #[test]
    fn status_note_says_gpu_in_use_by_other_work() {
        let n = serde_json::json!({"id": "host3", "gpu_contention": {"state": "yielded", "foreign_mb": 11468,
            "since": "2026-10-17T12:00:00Z", "paused_backends": ["vllm"]}});
        assert_eq!(gpu_status_note(&n).unwrap(),
            "host3: GPU in use by other work — vllm paused since 2026-10-17T12:00:00Z (foreign 11.2 GB)");
        let held = serde_json::json!({"id": "host3", "gpu_contention": {"state": "held", "reason": "voice", "paused_backends": ["vllm"]}});
        assert_eq!(gpu_status_note(&held).unwrap(), "host3: GPU held by operator (voice) — vllm paused");
        let owned = serde_json::json!({"id": "host3", "gpu_contention": {"state": "held", "reason": "voice", "paused_backends": ["vllm"],
            "lease": {"owner": "rbwolf", "operation_id": "op-1", "generation": 3}}});
        assert_eq!(gpu_status_note(&owned).unwrap(), "host3: GPU held by rbwolf (voice) — vllm paused");
        let draining = serde_json::json!({"id": "host3", "gpu_contention": {"state": "draining", "lease": {"owner": "rbwolf"}}});
        assert_eq!(gpu_status_note(&draining).unwrap(), "host3: GPU hold by rbwolf draining — waiting for requests in flight to finish");
        assert!(gpu_status_note(&serde_json::json!({"id": "x", "gpu_contention": {"state": "free"}})).is_none());
        assert!(gpu_status_note(&serde_json::json!({"id": "x"})).is_none());
    }
}
