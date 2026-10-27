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
//! renders into that key (#408), capped by the model's own ceiling from
//! `config/model-capabilities.json` (i226 phase C): no engine setting gives
//! a model more context than it was built for. A refusal the ceiling
//! decides names no window to raise. The GPU's room is not checked here.

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

/// The window one request gets on a chat placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    pub tokens: u64,
    /// Where the number came from, for the operator.
    pub source: String,
    /// The model's own ceiling decided it: a larger engine setting would
    /// not help.
    pub model_ceiling: bool,
}

/// The engine's setting for one placement, before the model's ceiling.
/// `None` for a backend this does not know how to read.
fn engine_window(backend: &str, env: &Value, profile_context: u64) -> Option<(u64, String)> {
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

/// The window one request gets on a chat placement serving `model`: the
/// engine's setting, capped by the model's own ceiling. With no engine
/// setting this can read, the ceiling alone is still an upper bound.
pub fn chat_window(backend: &str, env: &Value, model: Option<&str>, profile_context: u64) -> Option<Window> {
    let engine = engine_window(backend, env, profile_context);
    let ceiling = model.and_then(|m| crate::model_capabilities::max_context(m).map(|n| (n, m)));
    match (engine, ceiling) {
        (Some((n, source)), Some((c, _))) if n <= c => Some(Window { tokens: n, source, model_ceiling: false }),
        (Some((n, source)), None) => Some(Window { tokens: n, source, model_ceiling: false }),
        (_, Some((c, m))) => Some(Window { tokens: c, source: format!("{m}'s own context ceiling"), model_ceiling: true }),
        (None, None) => None,
    }
}

/// The smallest window across the node's running chat placements
/// (backend, env, model): the harness may be pinned to any of them.
pub fn node_window<'a>(chats: impl IntoIterator<Item = (&'a str, &'a Value, Option<&'a str>)>, profile_context: u64) -> Option<Window> {
    chats.into_iter().filter_map(|(b, env, m)| chat_window(b, env, m, profile_context)).min_by_key(|w| w.tokens)
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
    Tight { floor: u64, need: u64, window: u64, source: String, model_ceiling: bool },
    Short { floor: u64, need: u64, window: u64, source: String, model_ceiling: bool },
}

/// floor × [`HEADROOM`], rounded up.
pub fn need_for(floor: u64) -> u64 {
    (floor as f64 * HEADROOM).ceil() as u64
}

pub fn judge(floor: Option<u64>, window: Option<Window>) -> Fit {
    let (Some(floor), Some(Window { tokens: window, source, model_ceiling })) = (floor, window) else { return Fit::Unchecked };
    let need = need_for(floor);
    if window < floor {
        Fit::Short { floor, need, window, source, model_ceiling }
    } else if window < need {
        Fit::Tight { floor, need, window, source, model_ceiling }
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
    let (floor, need, window, source, short, model_ceiling) = match fit {
        Fit::Short { floor, need, window, source, model_ceiling } => (*floor, *need, *window, source, true, *model_ceiling),
        Fit::Tight { floor, need, window, source, model_ceiling } => (*floor, *need, *window, source, false, *model_ceiling),
        _ => return None,
    };
    let what = if short {
        format!("{kind} cannot run on {node}: its first request is about {floor} tokens (its prompt floor) and {node}'s chat window is {window} ({source})")
    } else {
        format!("{kind} on {node} is tight: its prompt floor is {floor} tokens, {window} ({source}) leaves less than the {need} it needs with headroom")
    };
    let key = chat.and_then(|(b, _)| window_keys(b)).map(|(k, _)| k[0]);
    let raise = match (chat, key) {
        // The model cannot take more: a larger engine setting changes nothing.
        _ if model_ceiling => "; a larger window needs a model built for one".to_string(),
        (Some((backend, model)), Some(key)) => format!("; raise the window: `noo cluster place {node} {backend} {model} --env {key}={}`", suggest(need)),
        _ => String::new(),
    };
    Some(format!("{what}. Fits here: noo (noomesh's own loop){raise}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn w(tokens: u64) -> Option<Window> {
        Some(Window { tokens, source: "x".into(), model_ceiling: false })
    }

    /// awolf on 2026-10-24: vLLM at the image default, no profile value.
    #[test]
    fn the_awolf_window_refuses_copilot_with_the_numbers() {
        let win = chat_window("vllm", &json!({"VLLM_MAX_MODEL_LEN": "16384"}), Some("gemma-4-12B-it-qat-w4a16-ct"), 32768);
        assert_eq!(win, Some(Window { tokens: 16384, source: "VLLM_MAX_MODEL_LEN on its vllm placement".to_string(), model_ceiling: false }));
        let fit = judge(Some(16385), win);
        assert!(matches!(fit, Fit::Short { floor: 16385, need: 20482, window: 16384, model_ceiling: false, .. }), "{fit:?}");
        let m = message("awolf", "copilot", &fit, Some(("vllm", "gemma-4-12b"))).unwrap();
        assert!(m.starts_with("copilot cannot run on awolf: its first request is about 16385 tokens"), "{m}");
        assert!(m.contains("Fits here: noo") && m.ends_with("`noo cluster place awolf vllm gemma-4-12b --env VLLM_MAX_MODEL_LEN=32768`"), "{m}");
    }

    #[test]
    fn the_profile_context_is_the_window_when_the_placement_sets_none() {
        assert_eq!(chat_window("ollama", &json!({}), None, 32768).map(|w| w.tokens), Some(32768));
        assert_eq!(judge(Some(16385), chat_window("ollama", &json!({}), None, 32768)), Fit::Fits);
        assert_eq!(chat_window("ollama", &json!({}), None, 0), None, "nothing to read");
        assert_eq!(chat_window("airllm", &json!({"N_CTX": 8192}), None, 32768), None, "an engine this cannot read");
    }

    #[test]
    fn llamacpp_shares_its_window_across_slots() {
        let win = chat_window("llamacpp", &json!({"LLAMA_ARG_CTX_SIZE": 32768, "LLAMA_ARG_N_PARALLEL": "2"}), None, 0).unwrap();
        assert_eq!(win.tokens, 16384);
        assert!(win.source.contains("shared by 2 parallel slots"), "{}", win.source);
        assert_eq!(chat_window("llamacpp", &json!({"N_CTX": "8192", "N_PARALLEL": 1}), None, 0).map(|w| w.tokens), Some(8192));
    }

    /// i226 phase C: an engine set above what the model was built for gets
    /// the model's ceiling, and a refusal it decides names no window to raise.
    #[test]
    fn the_models_own_ceiling_caps_the_engine_setting() {
        let declared = "gemma4:12b";
        let ceiling = crate::model_capabilities::max_context(declared).unwrap();
        let over = json!({"OLLAMA_CONTEXT_LENGTH": ceiling * 2});
        let win = chat_window("ollama", &over, Some(declared), 0).unwrap();
        assert_eq!((win.tokens, win.model_ceiling), (ceiling, true));
        assert_eq!(win.source, "gemma4:12b's own context ceiling");
        let under = chat_window("ollama", &json!({"OLLAMA_CONTEXT_LENGTH": 8192}), Some(declared), 0).unwrap();
        assert_eq!((under.tokens, under.model_ceiling), (8192, false), "below the ceiling the engine decides");
        assert_eq!(chat_window("airllm", &json!({}), Some(declared), 0).map(|w| w.tokens), Some(ceiling), "the ceiling alone is an upper bound");
        assert_eq!(chat_window("ollama", &over, Some("qwen3:8b"), 0).map(|w| w.model_ceiling), Some(false), "an undeclared model has no ceiling");

        let fit = judge(Some(ceiling + 1), Some(win));
        assert!(matches!(fit, Fit::Short { model_ceiling: true, .. }), "{fit:?}");
        let m = message("n", "copilot", &fit, Some(("ollama", declared))).unwrap();
        assert!(m.ends_with("Fits here: noo (noomesh's own loop); a larger window needs a model built for one"), "{m}");
        assert!(!m.contains("noo cluster place"), "{m}");
    }

    #[test]
    fn tight_unchecked_and_the_smallest_window() {
        let tight = judge(Some(16385), Some(Window { tokens: 18000, source: "x".into(), model_ceiling: false }));
        assert!(matches!(tight, Fit::Tight { need: 20482, .. }));
        assert!(message("n", "copilot", &tight, None).unwrap().contains("is tight"));
        assert_eq!(judge(None, w(1024)), Fit::Unchecked, "no floor declared: never refused");
        assert_eq!(judge(Some(16385), None), Fit::Unchecked);
        assert_eq!(message("n", "k", &Fit::Fits, None), None);
        let (a, b) = (json!({"VLLM_MAX_MODEL_LEN": 32768}), json!({"OLLAMA_CONTEXT_LENGTH": 8192}));
        assert_eq!(node_window([("vllm", &a, None), ("ollama", &b, None)], 0).map(|w| w.tokens), Some(8192));
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
