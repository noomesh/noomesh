//! `phase` frames: what a turn is doing before its first token, for the
//! console's phase line (noomesh/noomesh #624, agreed with the console
//! 2026-11-01). Two phases come from here:
//!
//! - `routed`: the node a model call went to, with that backend's slots
//!   (`slots_busy`/`slots_total`/`queued_ahead`, null when the agent reports
//!   none), the attempt (1, 2, ... within one call's failover) and, from
//!   attempt 2, the node it moved from and why. Sent before each call, again
//!   when the node agent says the request is waiting for a slot (`: queued
//!   ahead=N`), and by dispatch for a harness turn (`via: "harness"`).
//! - `prompt`: the backend took the request (its response began) and is
//!   reading the prompt, with the loop's token estimate of what was sent.
//!
//! "thinking" and the first token are read off the frames the console
//! already gets. `at_ms` (gateway clock) is for logs; the console times each
//! phase from the frame's receipt.

use serde_json::{json, Value};

use super::classes::Slots;

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// The node a call left, and why (attempt 2 on).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Moved {
    pub node: String,
    pub reason: String,
}

/// One `routed` frame. Busy is the larger of the agent's count and this
/// gateway's own live count (the same rule as routing's `full_rank`);
/// `queued_ahead` is the agent's queue when every slot is taken, else 0.
#[allow(clippy::too_many_arguments)]
pub(crate) fn routed(
    node: &str,
    backend: &str,
    model: &str,
    slots: Option<Slots>,
    gateway_in_flight: usize,
    attempt: usize,
    moved: Option<&Moved>,
    via: &str,
) -> Value {
    let (busy, total, ahead) = match slots.filter(|s| s.total > 0) {
        Some(s) => {
            let busy = (s.in_flight as usize).max(gateway_in_flight);
            let ahead = if busy >= s.total as usize { s.queued } else { 0 };
            (json!(busy), json!(s.total), json!(ahead))
        }
        None => (Value::Null, Value::Null, Value::Null),
    };
    let mut f = json!({
        "phase": "routed",
        "node": node,
        "backend": backend,
        "model": model,
        "slots_busy": busy,
        "slots_total": total,
        "queued_ahead": ahead,
        "attempt": attempt,
        "via": via,
        "at_ms": now_ms(),
    });
    if let Some(m) = moved {
        f["previous_node"] = json!(m.node);
        f["previous_reason"] = json!(short_reason(&m.reason));
    }
    f
}

/// The same `routed` frame, now that the node agent says the request waits
/// for a slot: every slot taken (from the response's `X-Noo-In-Flight` /
/// `X-Noo-Slots` when present), `ahead` requests in front of it.
pub(crate) fn queued(routed: &Value, ahead: u32, in_flight: Option<u32>, slots: Option<u32>) -> Value {
    let mut f = routed.clone();
    let total = slots.filter(|t| *t > 0).map(Value::from).unwrap_or_else(|| f["slots_total"].clone());
    let busy = match (in_flight, total.as_u64()) {
        (Some(b), Some(t)) => json!((b as u64).max(t)),
        (_, Some(t)) => json!(t),
        _ => Value::Null,
    };
    f["slots_total"] = total;
    f["slots_busy"] = busy;
    f["queued_ahead"] = json!(ahead);
    f["at_ms"] = json!(now_ms());
    f
}

/// `: queued ahead=N`, the node agent's first comment on a request that
/// waits for a slot (node-agent-go `admission.go`).
pub(crate) fn queued_ahead(line: &str) -> Option<u32> {
    line.strip_prefix(": queued ahead=")?.trim().parse().ok()
}

/// One `prompt` frame: the backend began answering; `input_tokens` is the
/// loop's estimate of the request (messages and tool schemas).
pub(crate) fn prompt(input_tokens: usize) -> Value {
    json!({"phase": "prompt", "input_tokens": input_tokens, "at_ms": now_ms()})
}

/// A failover reason as one short line: the console prints it in brackets.
fn short_reason(r: &str) -> String {
    let line = r.lines().next().unwrap_or("").trim();
    if line.chars().count() > 120 {
        format!("{}…", line.chars().take(119).collect::<String>())
    } else {
        line.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_routed_frame_carries_the_slots_the_attempt_and_where_it_moved_from() {
        let s = Slots { in_flight: 2, total: 2, queued: 1 };
        let f = routed("mcmini", "ollama", "gemma4:12b", Some(s), 0, 1, None, "gateway");
        assert_eq!(f["phase"], "routed");
        assert_eq!(f["node"], "mcmini");
        assert_eq!((f["slots_busy"].as_u64(), f["slots_total"].as_u64(), f["queued_ahead"].as_u64()), (Some(2), Some(2), Some(1)));
        assert_eq!(f["attempt"], 1);
        assert!(f.get("previous_node").is_none(), "attempt 1 names no previous node");
        // A free slot: nobody is ahead, whatever the agent's queue says.
        let f = routed("awolf", "vllm", "m", Some(Slots { in_flight: 1, total: 4, queued: 3 }), 0, 1, None, "gateway");
        assert_eq!((f["slots_busy"].as_u64(), f["queued_ahead"].as_u64()), (Some(1), Some(0)));
        // This gateway's own count fills a slot the heartbeat still showed free.
        let f = routed("awolf", "vllm", "m", Some(Slots { in_flight: 0, total: 1, queued: 2 }), 1, 1, None, "gateway");
        assert_eq!((f["slots_busy"].as_u64(), f["queued_ahead"].as_u64()), (Some(1), Some(2)));
        // Unknown slots are null, so the console says "sending to <node>".
        let f = routed("host8", "ollama", "m", None, 3, 2, Some(&Moved { node: "host3".into(), reason: "HTTP 502 (backend unreachable)\nmore".into() }), "gateway");
        assert!(f["slots_busy"].is_null() && f["slots_total"].is_null() && f["queued_ahead"].is_null());
        assert_eq!((f["attempt"].as_u64(), f["previous_node"].as_str()), (Some(2), Some("host3")));
        assert_eq!(f["previous_reason"], "HTTP 502 (backend unreachable)");
        assert!(f["at_ms"].as_u64().is_some_and(|t| t > 0));
    }

    #[test]
    fn the_agents_queued_comment_turns_the_routed_frame_into_a_queue() {
        assert_eq!(queued_ahead(": queued ahead=3"), Some(3));
        assert_eq!(queued_ahead(": keep-alive"), None);
        assert_eq!(queued_ahead("data: {}"), None);
        let r = routed("mcmini", "ollama", "m", Some(Slots { in_flight: 1, total: 2, queued: 0 }), 0, 1, None, "gateway");
        let q = queued(&r, 1, Some(2), Some(2));
        assert_eq!((q["slots_busy"].as_u64(), q["slots_total"].as_u64(), q["queued_ahead"].as_u64()), (Some(2), Some(2), Some(1)));
        assert_eq!((q["node"].as_str(), q["attempt"].as_u64()), (Some("mcmini"), Some(1)));
        // No occupancy headers and no known slots: still a queue, sizes unknown.
        let r = routed("mcmini", "ollama", "m", None, 0, 1, None, "gateway");
        let q = queued(&r, 2, None, None);
        assert!(q["slots_busy"].is_null() && q["slots_total"].is_null());
        assert_eq!(q["queued_ahead"], 2);
    }

    #[test]
    fn a_prompt_frame_carries_the_estimate() {
        let f = prompt(1834);
        assert_eq!((f["phase"].as_str(), f["input_tokens"].as_u64()), (Some("prompt"), Some(1834)));
    }
}
