// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster gpu hold|release <node>` — the operator's hand on a shared
//! GPU node (node agent `internal/gpuyield`).
//!
//! The agent yields its GPU backends on its own when foreign work takes the
//! GPU, but whoever starts first holds the GPU: a stack that refuses to start
//! while the GPU is occupied (pai-voice) can never get it from a running
//! vLLM. `hold` pauses the node's GPU backends now and keeps them paused;
//! `release` hands the node back to the automatic policy, which resumes them
//! once the GPU has stayed free. Operator-only and audited at the gateway.

use serde_json::Value;

use crate::http::post_json;
use crate::ui;
use crate::{Globals, Unhandled};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GpuArgs {
    Hold { node: String, reason: Option<String> },
    Release { node: String },
}

pub(crate) fn parse_gpu_hold(args: &[String]) -> Result<GpuArgs, ()> {
    let [node, rest @ ..] = args else { return Err(()) };
    if node.starts_with('-') {
        return Err(());
    }
    let mut reason = None;
    let mut it = rest.iter();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "--reason" => reason = Some(it.next().ok_or(())?.trim().to_string()).filter(|r| !r.is_empty()),
            _ => return Err(()),
        }
    }
    Ok(GpuArgs::Hold { node: node.clone(), reason })
}

pub(crate) fn parse_gpu_release(args: &[String]) -> Result<GpuArgs, ()> {
    match args {
        [node] if !node.starts_with('-') => Ok(GpuArgs::Release { node: node.clone() }),
        _ => Err(()),
    }
}

/// `noo cluster gpu hold <node> [--reason <text>]`
pub fn cluster_gpu_hold(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let Ok(GpuArgs::Hold { node, reason }) = parse_gpu_hold(args) else { return Err(Unhandled) };
    let resp = post_json(
        g,
        &format!("/api/cluster/nodes/{}/gpu/hold", super::urlencode(&node)),
        &serde_json::json!({"reason": reason.clone().unwrap_or_default()}),
        true,
        90,
    );
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let paused = paused_list(&resp["gpu_contention"]);
    ui::done(&format!("{node}: GPU held{} — {paused} paused; it stays paused until you release it",
        reason.map(|r| format!(" ({r})")).unwrap_or_default()));
    ui::guide(&[
        ("noo cluster gpu release <node>", "returns the node to automatic sharing: its GPU backends resume once the GPU is free"),
        ("noo cluster verify <node>", "the `gpu` row shows the hold"),
    ]);
    Ok(0)
}

/// `noo cluster gpu release <node>`
pub fn cluster_gpu_release(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let Ok(GpuArgs::Release { node }) = parse_gpu_release(args) else { return Err(Unhandled) };
    let resp = post_json(
        g,
        &format!("/api/cluster/nodes/{}/gpu/release", super::urlencode(&node)),
        &serde_json::json!({}),
        true,
        30,
    );
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    match resp["gpu_contention"]["state"].as_str() {
        Some("yielded") => ui::done(&format!(
            "{node}: hold released — {} resume once the GPU has stayed free (NOO_GPU_RESUME_AFTER_S, default 120 s)",
            paused_list(&resp["gpu_contention"]))),
        _ => ui::done(&format!("{node}: hold released; nothing was paused")),
    }
    Ok(0)
}

fn paused_list(gc: &Value) -> String {
    let names: Vec<&str> = gc["paused_backends"].as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if names.is_empty() { "no GPU backend".to_string() } else { names.join(", ") }
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
        "held" => Some(format!("{id}: GPU held by operator{} — {paused} paused{since}",
            gc["reason"].as_str().filter(|r| !r.is_empty()).map(|r| format!(" ({r})")).unwrap_or_default())),
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
            Ok(GpuArgs::Hold { node: "host3".into(), reason: Some("voice".into()) }));
        assert_eq!(parse_gpu_hold(&a(&["host3"])), Ok(GpuArgs::Hold { node: "host3".into(), reason: None }));
        assert!(parse_gpu_hold(&a(&[])).is_err());
        assert!(parse_gpu_hold(&a(&["host3", "--reason"])).is_err());
        assert!(parse_gpu_hold(&a(&["host3", "--bogus"])).is_err());
        assert_eq!(parse_gpu_release(&a(&["host3"])), Ok(GpuArgs::Release { node: "host3".into() }));
        assert!(parse_gpu_release(&a(&["host3", "x"])).is_err());
        assert!(parse_gpu_release(&a(&["--x"])).is_err());
    }

    #[test]
    fn status_note_says_gpu_in_use_by_other_work() {
        let n = serde_json::json!({"id": "host3", "gpu_contention": {"state": "yielded", "foreign_mb": 11468,
            "since": "2026-10-17T12:00:00Z", "paused_backends": ["vllm"]}});
        assert_eq!(gpu_status_note(&n).unwrap(),
            "host3: GPU in use by other work — vllm paused since 2026-10-17T12:00:00Z (foreign 11.2 GB)");
        let held = serde_json::json!({"id": "host3", "gpu_contention": {"state": "held", "reason": "voice", "paused_backends": ["vllm"]}});
        assert_eq!(gpu_status_note(&held).unwrap(), "host3: GPU held by operator (voice) — vllm paused");
        assert!(gpu_status_note(&serde_json::json!({"id": "x", "gpu_contention": {"state": "free"}})).is_none());
        assert!(gpu_status_note(&serde_json::json!({"id": "x"})).is_none());
    }
}
