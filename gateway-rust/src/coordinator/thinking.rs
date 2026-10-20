// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `NOO_HARNESS_THINKING=on|off|auto`: whether a model reasons before it
//! answers, decided per node.
//!
//! Why: a reasoning model on a slow node spends most of a call thinking.
//! gemma4:12b on an M4 (mcmini, 2026-10-17) took 3-4.5 min per model call,
//! mostly reasoning, and a three-call turn overran the 900 s turn deadline.
//! `off` there trades depth for an answer that arrives.
//!
//! - `auto` (the default, and anything unrecognised): today's behaviour, the
//!   caller's `enable_thinking` decides.
//! - `on`: `enable_thinking` is true for every call.
//! - `off`: `enable_thinking` is false for every call, AND each wire's own
//!   "do not reason" field is set ([`disable_on_wire`]), because
//!   `chat_template_kwargs` alone is a vLLM convention Ollama ignores.
//!
//! Where it comes from: on a node harness, the harness placement's env
//! (`noo cluster place <node> harness <model> --env NOO_HARNESS_THINKING=off`,
//! read from the node agent's `/harness/placement`) or the harness process's
//! own environment; on the controller, the gateway setting of the same name
//! (`noo_settings`, else the env). The harness sets the process-wide value
//! at start with [`set_process_mode`] and re-reads its placement every
//! minute; everything else reads [`thinking_mode`]. A translator (a foreign
//! CLI's task or turn) takes the value in force when it starts.

use std::sync::atomic::{AtomicU8, Ordering};

use serde_json::{json, Value};

/// The setting's name, in every place it is read.
pub const THINKING_ENV: &str = "NOO_HARNESS_THINKING";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThinkingMode {
    On,
    Off,
    Auto,
}

/// `on|off|auto` (also `true/false/1/0/yes/no`); blank or anything else is
/// `auto`: a typo keeps today's behaviour rather than switching reasoning
/// off on a node nobody meant to change.
pub fn parse_thinking_mode(raw: Option<&str>) -> ThinkingMode {
    match raw.map(|r| r.trim().to_ascii_lowercase()).as_deref() {
        Some("on") | Some("true") | Some("1") | Some("yes") => ThinkingMode::On,
        Some("off") | Some("false") | Some("0") | Some("no") => ThinkingMode::Off,
        _ => ThinkingMode::Auto,
    }
}

/// 0 = not decided by the process (read the setting); else a mode.
static PROCESS_MODE: AtomicU8 = AtomicU8::new(0);

/// The harness's decision, from its env and its placement: made at start
/// and re-made when the placement changes (the harness re-reads it every
/// minute). Returns the previous decision, if there was one.
pub fn set_process_mode(mode: ThinkingMode) -> Option<ThinkingMode> {
    let code = match mode {
        ThinkingMode::On => 1,
        ThinkingMode::Off => 2,
        ThinkingMode::Auto => 3,
    };
    decode(PROCESS_MODE.swap(code, Ordering::Relaxed))
}

fn decode(code: u8) -> Option<ThinkingMode> {
    match code {
        1 => Some(ThinkingMode::On),
        2 => Some(ThinkingMode::Off),
        3 => Some(ThinkingMode::Auto),
        _ => None,
    }
}

/// The mode in force: the harness's process-wide decision when it made
/// one, else the setting (`noo_settings` override, then the env).
pub fn thinking_mode() -> ThinkingMode {
    if let Some(m) = decode(PROCESS_MODE.load(Ordering::Relaxed)) {
        return m;
    }
    parse_thinking_mode(crate::settings::get(THINKING_ENV).as_deref())
}

/// The `enable_thinking` a call goes out with under `mode`.
pub fn effective_enable_thinking(mode: ThinkingMode, requested: bool) -> bool {
    match mode {
        ThinkingMode::On => true,
        ThinkingMode::Off => false,
        ThinkingMode::Auto => requested,
    }
}

/// Whether an OpenAI chat body asks for no reasoning itself: `reasoning:
/// {effort: "none"}` (what a Responses `reasoning.effort` of none or minimal
/// becomes, `responses_wire`), or `reasoning_effort` none/minimal. Its
/// caller then sets every engine's field with [`disable_on_wire`], since
/// the one the client sent reaches only some engines (noomesh-internal
/// i153).
pub fn asks_no_reasoning(body: &Value) -> bool {
    let off = |v: Option<&Value>| v.and_then(Value::as_str).is_some_and(|e| e.eq_ignore_ascii_case("none") || e.eq_ignore_ascii_case("minimal"));
    off(body.pointer("/reasoning/effort")) || off(body.get("reasoning_effort"))
}

/// Set every "do not reason" field `wire` understands on a request body
/// already built for that wire. `wire` is the protocol on the wire
/// (`backend::wire_format`: `openai`, `ollama`, `llamacpp`, `anthropic`);
/// `backend_type` names the engine behind it (the node agent's
/// `X-Noo-Backend`), which matters for the OpenAI-compatible surface:
///
/// - Ollama's `/api/chat`: `"think": false`.
/// - The OpenAI-compatible surface: `chat_template_kwargs.enable_thinking =
///   false` (vLLM, llama.cpp with `--jinja`: the chat template's switch) AND
///   `"reasoning": {"effort": "none"}`, which Ollama's OpenAI layer maps to
///   `think: false` and which vLLM and llama-server ignore as an unknown
///   field. Both, always, because a harness speaks to its node agent's proxy
///   as `openai` (`NOO_HARNESS_BACKEND=openai`) and does not know which
///   engine is behind it: on mcmini that engine is Ollama, which ignores
///   `chat_template_kwargs`. When the backend type does say `ollama`,
///   `"think": false` too. Not `reasoning_effort`: vLLM validates it
///   against `low|medium|high` and would refuse `none`. Not on a cloud
///   provider: a provider rejects fields it does not know.
/// - llama.cpp's legacy `/completion` and Anthropic: nothing to set.
pub fn disable_on_wire(body: &mut Value, wire: &str, backend_type: &str, cloud: bool) {
    if cloud || !body.is_object() {
        return;
    }
    match wire {
        "ollama" => {
            body["think"] = json!(false);
        }
        "openai" => {
            if !body.get("chat_template_kwargs").is_some_and(Value::is_object) {
                body["chat_template_kwargs"] = json!({});
            }
            body["chat_template_kwargs"]["enable_thinking"] = json!(false);
            body["reasoning"] = json!({"effort": "none"});
            if backend_type.eq_ignore_ascii_case("ollama") {
                body["think"] = json!(false);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_asks_for_no_reasoning_by_either_field() {
        assert!(asks_no_reasoning(&json!({"reasoning": {"effort": "none"}})));
        assert!(asks_no_reasoning(&json!({"reasoning_effort": "Minimal"})));
        assert!(!asks_no_reasoning(&json!({"reasoning_effort": "low"})));
        assert!(!asks_no_reasoning(&json!({"reasoning": {"effort": "high"}})));
        assert!(!asks_no_reasoning(&json!({"messages": []})));
    }

    #[test]
    fn the_setting_parses_strictly_and_a_typo_is_auto() {
        assert_eq!(parse_thinking_mode(Some("off")), ThinkingMode::Off);
        assert_eq!(parse_thinking_mode(Some(" OFF ")), ThinkingMode::Off);
        assert_eq!(parse_thinking_mode(Some("false")), ThinkingMode::Off);
        assert_eq!(parse_thinking_mode(Some("on")), ThinkingMode::On);
        assert_eq!(parse_thinking_mode(Some("auto")), ThinkingMode::Auto);
        assert_eq!(parse_thinking_mode(Some("")), ThinkingMode::Auto);
        assert_eq!(parse_thinking_mode(Some("of")), ThinkingMode::Auto);
        assert_eq!(parse_thinking_mode(None), ThinkingMode::Auto);
    }

    #[test]
    fn the_mode_overrides_the_request_only_when_it_says_so() {
        for requested in [true, false] {
            assert_eq!(effective_enable_thinking(ThinkingMode::Auto, requested), requested);
            assert!(effective_enable_thinking(ThinkingMode::On, requested));
            assert!(!effective_enable_thinking(ThinkingMode::Off, requested));
        }
    }

    #[test]
    fn off_sets_each_wires_own_field() {
        // Ollama's native /api/chat.
        let mut b = json!({"model": "gemma4:12b", "messages": [], "stream": true});
        disable_on_wire(&mut b, "ollama", "ollama", false);
        assert_eq!(b["think"], false);

        // The OpenAI surface in front of vLLM: the chat template's switch,
        // plus the reasoning object it ignores.
        let mut b = json!({"model": "g", "chat_template_kwargs": {"enable_thinking": true, "x": 1}});
        disable_on_wire(&mut b, "openai", "vllm", false);
        assert_eq!(b["chat_template_kwargs"], json!({"enable_thinking": false, "x": 1}));
        assert_eq!(b["reasoning"], json!({"effort": "none"}));
        assert!(b.get("think").is_none(), "vLLM gets no Ollama-only field");
        assert!(b.get("reasoning_effort").is_none(), "vLLM refuses reasoning_effort=none");

        // A harness's `openai` backend through its node agent: the engine is
        // unknown, so Ollama's OpenAI-layer switch rides along.
        let mut b = json!({"model": "auto"});
        disable_on_wire(&mut b, "openai", "openai", false);
        assert_eq!(b["reasoning"]["effort"], "none");
        assert_eq!(b["chat_template_kwargs"]["enable_thinking"], false);

        // Named Ollama behind the OpenAI surface: its native field as well.
        let mut b = json!({"model": "g"});
        disable_on_wire(&mut b, "openai", "ollama", false);
        assert_eq!(b["think"], false);
        assert_eq!(b["reasoning"]["effort"], "none");

        // A cloud provider and the wires with no switch are untouched.
        for (wire, cloud) in [("openai", true), ("anthropic", false), ("llamacpp", false)] {
            let mut b = json!({"model": "m"});
            disable_on_wire(&mut b, wire, "cloud-openai", cloud);
            assert_eq!(b, json!({"model": "m"}), "{wire} cloud={cloud}");
        }
    }
}
