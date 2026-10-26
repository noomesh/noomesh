// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Does a harness kind fit a node's context window? (i226 phase B)
//!
//! A kind has a prompt floor (`min_context_tokens` in
//! `config/harness-kinds.json`, measured by `noo-gateway harness probe`):
//! the size of its CLI's first request to the model. A node whose chat
//! window is below it cannot run the kind at all. On 2026-10-24 every
//! vendor kind failed on awolf's 16 384-token vLLM window that way, with a
//! 400 on the first request and nothing at placement time to say so.
//!
//! The verdict, pure ([`judge`]):
//! - window below the floor: `Short`, refused at placement unless `force`;
//! - at least the floor but below floor × [`HEADROOM`]: `Tight`, placed with
//!   a warning (room for the task text and the answer is thin);
//! - otherwise `Fits`;
//! - no declared floor, or no window this can read: `Unchecked`, never a
//!   refusal. A guess does not block a placement.
//!
//! The window is the node's running chat placement's own engine key when it
//! sets one, else the harness profile's `context`, which the node agent
//! renders into that key (#408). The model's own ceiling and the GPU's
//! room are i226 phase C.

use serde_json::Value;

/// The room a kind needs beyond its floor (i226 decision 2).
pub const HEADROOM: f64 = 1.25;

/// The engine keys that set a chat backend's window, first one wins, and
/// the keys that divide it across parallel slots (llama-server's
/// `--ctx-size` is shared by its slots).
fn window_keys(backend: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    match backend {
        "vllm" | "vllm-secondary" => Some((&["VLLM_MAX_MODEL_LEN"], &[])),
        "ollama" => Some((&["OLLAMA_CONTEXT_LENGTH"], &[])),
        "llamacpp" => Some((&["N_CTX", "LLAMA_ARG_CTX_SIZE"], &["N_PARALLEL", "LLAMA_ARG_N_PARALLEL"])),
        _ => None,
    }
}

fn env_u64(env: &Value, key: &str) -> Option<u64> {
    let n = match env.get(key)? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    };
    n.filter(|n| *n > 0)
}

/// The window one request gets on a chat placement, and where it came
/// from. `None` for a backend this does not know how to read.
pub fn chat_window(backend: &str, env: &Value, profile_context: u64) -> Option<(u64, String)> {
    let (keys, slots) = window_keys(backend)?;
    let (total, source) = match keys.iter().find_map(|k| env_u64(env, k).map(|n| (n, *k))) {
        Some((n, k)) => (n, format!("{k} on its {backend} placement")),
        None if profile_context > 0 => (profile_context, format!("the harness profile's context, rendered into {backend}")),
        None => return None,
    };
    match slots.iter().find_map(|k| env_u64(env, k)).filter(|n| *n > 1) {
        Some(n) => Some((total / n, format!("{source}, shared by {n} parallel slots"))),
        None => Some((total, source)),
    }
}

/// The smallest window across the node's running chat placements: the
/// harness may be pinned to any of them.
pub fn node_window<'a>(chats: impl IntoIterator<Item = (&'a str, &'a Value)>, profile_context: u64) -> Option<(u64, String)> {
    chats.into_iter().filter_map(|(b, env)| chat_window(b, env, profile_context)).min_by_key(|(n, _)| *n)
}

/// The floor a kind runs at on this node: the slim launch's when the
/// node's profile picks it and the kind has one.
pub fn kind_floor(kind: &crate::harness_kinds::HarnessKind, slim: bool) -> Option<u64> {
    if slim && kind.launch_slim.is_some() {
        kind.min_context_tokens_slim
    } else {
        kind.min_context_tokens
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fit {
    Unchecked,
    Fits,
    Tight { floor: u64, need: u64, window: u64, source: String },
    Short { floor: u64, need: u64, window: u64, source: String },
}

/// floor × [`HEADROOM`], rounded up.
pub fn need_for(floor: u64) -> u64 {
    (floor as f64 * HEADROOM).ceil() as u64
}

pub fn judge(floor: Option<u64>, window: Option<(u64, String)>) -> Fit {
    let (Some(floor), Some((window, source))) = (floor, window) else { return Fit::Unchecked };
    let need = need_for(floor);
    if window < floor {
        Fit::Short { floor, need, window, source }
    } else if window < need {
        Fit::Tight { floor, need, window, source }
    } else {
        Fit::Fits
    }
}

/// The smallest power of two at least `n`: a window to suggest.
fn suggest(n: u64) -> u64 {
    n.max(1).next_power_of_two()
}

/// What an operator reads for `Short` or `Tight`: the numbers, what fits,
/// and how to raise the window. `chat` is the placement whose key to raise
/// (backend, model).
pub fn message(node: &str, kind: &str, fit: &Fit, chat: Option<(&str, &str)>) -> Option<String> {
    let (floor, need, window, source, short) = match fit {
        Fit::Short { floor, need, window, source } => (*floor, *need, *window, source, true),
        Fit::Tight { floor, need, window, source } => (*floor, *need, *window, source, false),
        _ => return None,
    };
    let what = if short {
        format!("{kind} cannot run on {node}: its first request is about {floor} tokens (its prompt floor) and {node}'s chat window is {window} ({source})")
    } else {
        format!("{kind} on {node} is tight: its prompt floor is {floor} tokens, {window} ({source}) leaves less than the {need} it needs with headroom")
    };
    let key = chat.and_then(|(b, _)| window_keys(b)).map(|(k, _)| k[0]);
    let raise = match (chat, key) {
        (Some((backend, model)), Some(key)) => format!("; raise the window: `noo cluster place {node} {backend} {model} --env {key}={}`", suggest(need)),
        _ => String::new(),
    };
    Some(format!("{what}. Fits here: noo (noomesh's own loop){raise}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// awolf on 2026-10-24: vLLM at the image default, no profile value.
    #[test]
    fn the_awolf_window_refuses_copilot_with_the_numbers() {
        let w = chat_window("vllm", &json!({"VLLM_MAX_MODEL_LEN": "16384"}), 32768);
        assert_eq!(w, Some((16384, "VLLM_MAX_MODEL_LEN on its vllm placement".to_string())));
        let fit = judge(Some(16385), w);
        assert!(matches!(fit, Fit::Short { floor: 16385, need: 20482, window: 16384, .. }), "{fit:?}");
        let m = message("awolf", "copilot", &fit, Some(("vllm", "gemma-4-12b"))).unwrap();
        assert!(m.starts_with("copilot cannot run on awolf: its first request is about 16385 tokens"), "{m}");
        assert!(m.contains("Fits here: noo") && m.ends_with("`noo cluster place awolf vllm gemma-4-12b --env VLLM_MAX_MODEL_LEN=32768`"), "{m}");
    }

    #[test]
    fn the_profile_context_is_the_window_when_the_placement_sets_none() {
        assert_eq!(chat_window("ollama", &json!({}), 32768).map(|w| w.0), Some(32768));
        assert_eq!(judge(Some(16385), chat_window("ollama", &json!({}), 32768)), Fit::Fits);
        assert_eq!(chat_window("ollama", &json!({}), 0), None, "nothing to read");
        assert_eq!(chat_window("airllm", &json!({"N_CTX": 8192}), 32768), None, "an engine this cannot read");
    }

    #[test]
    fn llamacpp_shares_its_window_across_slots() {
        let w = chat_window("llamacpp", &json!({"LLAMA_ARG_CTX_SIZE": 32768, "LLAMA_ARG_N_PARALLEL": "2"}), 0).unwrap();
        assert_eq!(w.0, 16384);
        assert!(w.1.contains("shared by 2 parallel slots"), "{}", w.1);
        assert_eq!(chat_window("llamacpp", &json!({"N_CTX": "8192", "N_PARALLEL": 1}), 0).map(|w| w.0), Some(8192));
    }

    #[test]
    fn tight_unchecked_and_the_smallest_window() {
        let tight = judge(Some(16385), Some((18000, "x".into())));
        assert!(matches!(tight, Fit::Tight { need: 20482, .. }));
        assert!(message("n", "copilot", &tight, None).unwrap().contains("is tight"));
        assert_eq!(judge(None, Some((1024, "x".into()))), Fit::Unchecked, "no floor declared: never refused");
        assert_eq!(judge(Some(16385), None), Fit::Unchecked);
        assert_eq!(message("n", "k", &Fit::Fits, None), None);
        let (a, b) = (json!({"VLLM_MAX_MODEL_LEN": 32768}), json!({"OLLAMA_CONTEXT_LENGTH": 8192}));
        assert_eq!(node_window([("vllm", &a), ("ollama", &b)], 0).map(|w| w.0), Some(8192));
    }

    #[test]
    fn the_shipped_floors_are_the_measured_ones() {
        let kind = |k: &str| crate::harness_kinds::get(k).unwrap();
        assert_eq!(kind_floor(kind("copilot"), false), Some(16385));
        assert_eq!(kind_floor(kind("claude-code"), false), Some(16385));
        assert_eq!(kind_floor(kind("claude-code"), true), None, "slim is not measured yet");
        assert_eq!(kind_floor(kind("codex"), false), None);
        assert_eq!(kind_floor(kind("noo"), false), None);
        assert_eq!(kind_floor(kind("copilot"), true), Some(16385), "no slim launch: the full floor");
    }
}
