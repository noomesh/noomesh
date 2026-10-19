// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The node's harness profile, as the harness reads it.
//!
//! The gateway resolves a per-node profile (tier default, measured speed,
//! per-node override: `config/harness-profiles.json`, `noo cluster profile`)
//! and the node agent hands it to its harness inside `GET
//! /harness/placement` as `profile`. Every field is optional here: an older
//! agent sends no `profile`, a newer one may add fields this binary does not
//! know, and a value of the wrong type or out of range is IGNORED (the
//! built-in default stands) rather than refusing the harness.
//!
//! What the harness applies, and in which order (process env > placement
//! env > profile > built-in default):
//!
//! - `thinking` → `NOO_HARNESS_THINKING` (`harness_main::resolve_thinking`);
//! - `stream_idle_secs` → `NOO_BACKEND_STREAM_IDLE_SECS`
//!   ([`resolve_stream_idle`], set once at start with
//!   `tls::set_stream_idle_override`, process-wide);
//! - `claude_prompt` → which Claude Code launch variant the driver uses
//!   (`launch` or `launch_slim`, [`ClaudePrompt`]).
//!
//! `first_byte_secs`, `ollama_context` and `foreign_kinds` are the node
//! agent's; they are parsed so a report can show them, not applied here.

use serde_json::Value;

use crate::coordinator::thinking::ThinkingMode;

/// The longest bound any profile number may carry (the gateway validates
/// overrides against the same ceiling).
pub const MAX_PROFILE_SECS: u64 = 7200;

/// Which Claude Code launch variant the driver runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClaudePrompt {
    /// The kind's `launch`: Claude Code's own system prompt and built-in tools.
    #[default]
    Full,
    /// The kind's `launch_slim`: a short system prompt and only the file
    /// tools beside noomesh's MCP tools, for a small model's prefill.
    Slim,
}

impl ClaudePrompt {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "full" => Some(Self::Full),
            "slim" => Some(Self::Slim),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Slim => "slim",
        }
    }
}

/// The resolved profile's fields the harness reads (contract §4).
/// `tier`, `first_byte_secs`, `ollama_context` and `foreign_kinds` are the
/// node agent's to apply; the harness only logs them.
#[derive(Clone, Debug, Default, PartialEq)]
#[allow(dead_code)]
pub struct HarnessProfile {
    pub tier: Option<u64>,
    pub first_byte_secs: Option<u64>,
    pub stream_idle_secs: Option<u64>,
    pub thinking: Option<ThinkingMode>,
    pub ollama_context: Option<u64>,
    pub claude_prompt: Option<ClaudePrompt>,
    pub foreign_kinds: Option<Vec<String>>,
}

/// A positive whole number no larger than `max`.
fn bounded(v: Option<&Value>, max: u64) -> Option<u64> {
    v.and_then(Value::as_u64).filter(|n| *n > 0 && *n <= max)
}

/// `on|off|auto` exactly — unlike the env reader, an unknown word in the
/// profile is not "auto" but absent, so the next source down decides.
fn thinking(v: Option<&Value>) -> Option<ThinkingMode> {
    match v.and_then(Value::as_str).map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("on") => Some(ThinkingMode::On),
        Some("off") => Some(ThinkingMode::Off),
        Some("auto") => Some(ThinkingMode::Auto),
        _ => None,
    }
}

impl HarnessProfile {
    /// The `profile` object of a `/harness/placement` answer; `None` when
    /// the answer carries none (an older agent) or it is not an object.
    pub fn from_placement(placement: &Value) -> Option<Self> {
        placement.get("profile").filter(|p| p.is_object()).map(Self::from_value)
    }

    /// The profile object itself.
    pub fn from_value(p: &Value) -> Self {
        Self {
            tier: bounded(p.get("tier"), 9),
            first_byte_secs: bounded(p.get("first_byte_secs"), MAX_PROFILE_SECS),
            stream_idle_secs: bounded(p.get("stream_idle_secs"), MAX_PROFILE_SECS),
            thinking: thinking(p.get("thinking")),
            // A context length is tokens, not seconds: no 7200 ceiling.
            ollama_context: p.get("ollama_context").and_then(Value::as_u64).filter(|n| *n > 0),
            claude_prompt: p.get("claude_prompt").and_then(Value::as_str).and_then(ClaudePrompt::parse),
            foreign_kinds: p.get("foreign_kinds").and_then(Value::as_array).map(|a| {
                a.iter().filter_map(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
            }),
        }
    }
}

/// The stream idle bound for this harness and where it came from:
/// `NOO_BACKEND_STREAM_IDLE_SECS` from the process env when it is set (the
/// env reader in `tls::stream_idle` then decides, a bad value included:
/// `None`), else the same key in the placement's env (a positive whole
/// number of seconds; anything else is skipped), else the profile's
/// `stream_idle_secs`, else `None` (`tls::DEFAULT_STREAM_IDLE_SECS`).
pub fn resolve_stream_idle(env_val: Option<&str>, placement_env_val: Option<&str>, profile: Option<&HarnessProfile>) -> (Option<u64>, &'static str) {
    if env_val.is_some_and(|v| !v.trim().is_empty()) {
        return (None, "env");
    }
    if let Some(s) = placement_env_val.and_then(|v| v.trim().parse::<u64>().ok()).filter(|s| *s > 0) {
        return (Some(s), "placement");
    }
    match profile.and_then(|p| p.stream_idle_secs) {
        Some(s) => (Some(s), "profile"),
        None => (None, "default"),
    }
}

/// The Claude Code launch variant: an explicit choice (the probe's
/// `--prompt`) > the profile > full.
pub fn resolve_claude_prompt(explicit: Option<ClaudePrompt>, profile: Option<&HarnessProfile>) -> (ClaudePrompt, &'static str) {
    if let Some(p) = explicit {
        return (p, "flag");
    }
    match profile.and_then(|p| p.claude_prompt) {
        Some(p) => (p, "profile"),
        None => (ClaudePrompt::Full, "default"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_profile_parses_from_a_placement_answer() {
        let body = json!({
            "kind": "claude-code", "env": {}, "desired_state": "running", "placed": true,
            "profile": {
                "tier": 2, "first_byte_secs": 600, "stream_idle_secs": 300, "thinking": "off",
                "ollama_context": 32768, "claude_prompt": "slim", "foreign_kinds": ["claude-code", "codex", "copilot"],
                "sources": {"first_byte_secs": "measured", "thinking": "override"},
                "bench": null
            }
        });
        let p = HarnessProfile::from_placement(&body).expect("a profile");
        assert_eq!(
            p,
            HarnessProfile {
                tier: Some(2),
                first_byte_secs: Some(600),
                stream_idle_secs: Some(300),
                thinking: Some(ThinkingMode::Off),
                ollama_context: Some(32768),
                claude_prompt: Some(ClaudePrompt::Slim),
                foreign_kinds: Some(vec!["claude-code".into(), "codex".into(), "copilot".into()]),
            }
        );
    }

    #[test]
    fn an_absent_or_broken_profile_leaves_every_field_to_the_next_source() {
        assert_eq!(HarnessProfile::from_placement(&json!({"placed": true, "kind": "noo"})), None, "an older agent");
        assert_eq!(HarnessProfile::from_placement(&json!({"profile": null})), None);
        assert_eq!(HarnessProfile::from_placement(&json!({"profile": "slim"})), None);
        let p = HarnessProfile::from_placement(&json!({"profile": {
            "first_byte_secs": 0, "stream_idle_secs": 7201, "thinking": "maybe", "claude_prompt": "tiny",
            "ollama_context": -1, "foreign_kinds": "codex", "tier": "2"
        }}))
        .unwrap();
        assert_eq!(p, HarnessProfile::default(), "every out-of-range or mistyped value is ignored");
        let p = HarnessProfile::from_value(&json!({"stream_idle_secs": 7200, "thinking": " AUTO ", "claude_prompt": "Full", "foreign_kinds": []}));
        assert_eq!((p.stream_idle_secs, p.thinking, p.claude_prompt), (Some(7200), Some(ThinkingMode::Auto), Some(ClaudePrompt::Full)));
        assert_eq!(p.foreign_kinds, Some(vec![]), "an empty list is a list: nothing foreign offered");
    }

    #[test]
    fn stream_idle_is_env_then_placement_env_then_profile_then_default() {
        let p = HarnessProfile { stream_idle_secs: Some(600), ..Default::default() };
        assert_eq!(resolve_stream_idle(Some("90"), Some("120"), Some(&p)), (None, "env"), "the env reader keeps the env value");
        assert_eq!(resolve_stream_idle(Some("  "), Some("120"), Some(&p)), (Some(120), "placement"), "a blank env is unset");
        assert_eq!(resolve_stream_idle(None, Some("0"), Some(&p)), (Some(600), "profile"), "an unusable placement value is skipped");
        assert_eq!(resolve_stream_idle(None, Some("soon"), Some(&p)), (Some(600), "profile"));
        assert_eq!(resolve_stream_idle(None, None, Some(&p)), (Some(600), "profile"));
        assert_eq!(resolve_stream_idle(None, None, Some(&HarnessProfile::default())), (None, "default"));
        assert_eq!(resolve_stream_idle(None, None, None), (None, "default"));
    }

    #[test]
    fn the_claude_prompt_is_flag_then_profile_then_full() {
        let slim = HarnessProfile { claude_prompt: Some(ClaudePrompt::Slim), ..Default::default() };
        assert_eq!(resolve_claude_prompt(Some(ClaudePrompt::Full), Some(&slim)), (ClaudePrompt::Full, "flag"));
        assert_eq!(resolve_claude_prompt(None, Some(&slim)), (ClaudePrompt::Slim, "profile"));
        assert_eq!(resolve_claude_prompt(None, Some(&HarnessProfile::default())), (ClaudePrompt::Full, "default"));
        assert_eq!(resolve_claude_prompt(None, None), (ClaudePrompt::Full, "default"));
        assert_eq!(ClaudePrompt::parse(" SLIM "), Some(ClaudePrompt::Slim));
        assert_eq!(ClaudePrompt::parse("short"), None);
        assert_eq!(ClaudePrompt::Slim.name(), "slim");
    }
}
