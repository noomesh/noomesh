// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The harness profile: per node, how long its inference proxy waits for a
//! first byte, how long a stream may idle, the harness's thinking default,
//! its context window (`context`, rendered into whichever engine the node
//! runs), which Claude Code launch variant it uses, and which
//! foreign harness kinds it may run.
//!
//! Declared ONCE per node TIER in `config/harness-profiles.json`, embedded
//! here at compile time. Per field the resolution is
//! **override > measured > tier default** ([`resolve`]):
//!
//! * override — `noo_node_config.harness_profile`, any subset of the
//!   fields, written by `noo cluster profile <node> --set k=v` and checked by
//!   [`validate_overrides`];
//! * measured — the node's heartbeat `model_bench` (`POST /bench` on the
//!   agent, `noo cluster profile <node> --bench`). It refines
//!   `first_byte_secs` ONLY, and only when the bench is of the model the
//!   node's chat backend runs now: a bench of another model says nothing
//!   about this one;
//! * tier default — the table row for the node's derived tier; a tier the
//!   table does not list (or none) reads as `unknown_tier`.
//!
//! The resolved profile ([`ResolvedProfile`]) ships to the node in
//! `GET /api/cluster/nodes/{id}/desired-config` as `harness_profile`.
//!
//! The path is a literal `../../config/...` (not `concat!(env!(...))`) so
//! `tests/test_rust_build_context_complete.py` sees it and holds the Docker
//! builder stage's COPY list to it.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

const RAW: &str = include_str!("../../config/harness-profiles.json");

/// The six fields, in declared order (the table's `fields` is held equal by
/// a test).
pub const FIELDS: [&str; 6] = [
    "first_byte_secs",
    "stream_idle_secs",
    "thinking",
    "context",
    "claude_prompt",
    "foreign_kinds",
];

/// The bound on the two `*_secs` overrides (two hours).
pub const MAX_SECS: u64 = 7200;
/// The bound on a `context` override (tokens).
pub const MAX_CONTEXT: u64 = 1_048_576;

/// `context`'s name until 0.6.13 (i226 decision 1). Accepted for one
/// release: as an override key (stored as `context`), in a stored row
/// written before the rename, and sent beside `context` in desired-config
/// for node agents older than 0.6.13, which read only this key. Remove once
/// every node runs 0.6.13.
pub const CONTEXT_ALIAS: &str = "ollama_context";

/// One tier's defaults.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct TierDefaults {
    pub first_byte_secs: u64,
    pub stream_idle_secs: u64,
    pub thinking: String,
    #[serde(alias = "ollama_context")]
    pub context: u64,
    pub claude_prompt: String,
    pub foreign_kinds: Vec<String>,
}

/// How a bench becomes a first-byte wait.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct MeasuredRule {
    pub reference_prompt_tokens: f64,
    pub headroom: f64,
    pub max_first_byte_secs: u64,
}

/// `config/harness-profiles.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct Table {
    /// Held equal to [`FIELDS`] by a test; nothing reads it at run time.
    #[allow(dead_code)]
    pub fields: Vec<String>,
    pub tiers: BTreeMap<String, TierDefaults>,
    pub unknown_tier: String,
    pub measured: MeasuredRule,
}

static TABLE: LazyLock<Table> =
    LazyLock::new(|| serde_json::from_str(RAW).expect("config/harness-profiles.json is malformed"));

/// The shipped table.
pub fn table() -> &'static Table {
    &TABLE
}

/// A node's measured model speed: the heartbeat `model_bench` the node
/// agent's `POST /bench` produces and reports on every beat after.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ModelBench {
    pub model: String,
    #[serde(default)]
    pub backend: Option<String>,
    pub load_secs: f64,
    pub prefill_tps: f64,
    #[serde(default)]
    pub decode_tps: Option<f64>,
    #[serde(default)]
    pub prompt_tokens: Option<u64>,
    #[serde(default)]
    pub at: Option<String>,
}

impl ModelBench {
    /// The record's `model_bench`, when present and well-formed.
    pub fn from_record(record: &Value) -> Option<ModelBench> {
        record.get("model_bench").filter(|v| v.is_object()).and_then(|v| serde_json::from_value(v.clone()).ok())
    }
}

/// The resolved profile, as `desired-config` carries it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedProfile {
    pub tier: u8,
    pub first_byte_secs: u64,
    pub stream_idle_secs: u64,
    pub thinking: String,
    pub context: u64,
    /// `context` again under [`CONTEXT_ALIAS`], for node agents older than
    /// 0.6.13. Always equal to `context`.
    #[serde(rename = "ollama_context")]
    pub context_alias: u64,
    pub claude_prompt: String,
    pub foreign_kinds: Vec<String>,
    /// Per field: `override` | `measured` | `tier`.
    pub sources: BTreeMap<String, String>,
    /// The node's bench, whether or not it applied (null before one ran).
    pub bench: Option<ModelBench>,
}

/// The foreign harness kinds (`config/harness-kinds.json` rows that run a
/// vendor CLI).
fn foreign_kinds() -> Vec<&'static str> {
    crate::harness_kinds::all().iter().filter(|k| k.cli.is_some()).map(|k| k.kind.as_str()).collect()
}

fn check_secs(field: &str, v: &Value) -> Result<Value, String> {
    match v.as_u64() {
        Some(n) if (1..=MAX_SECS).contains(&n) => Ok(json!(n)),
        _ => Err(format!("{field} must be a whole number of seconds, 1..={MAX_SECS}")),
    }
}

/// Judge ONE field's override value; `Ok` carries the normalised value.
fn check_field(field: &str, v: &Value) -> Result<Value, String> {
    match field {
        "first_byte_secs" | "stream_idle_secs" => check_secs(field, v),
        "context" | CONTEXT_ALIAS => match v.as_u64() {
            Some(n) if (1..=MAX_CONTEXT).contains(&n) => Ok(json!(n)),
            _ => Err(format!("context must be a whole number of tokens, 1..={MAX_CONTEXT}")),
        },
        "thinking" => match v.as_str().map(str::trim) {
            Some(s @ ("on" | "off" | "auto")) => Ok(json!(s)),
            _ => Err("thinking must be on, off or auto".into()),
        },
        "claude_prompt" => match v.as_str().map(str::trim) {
            Some(s @ ("full" | "slim")) => Ok(json!(s)),
            _ => Err("claude_prompt must be full or slim".into()),
        },
        "foreign_kinds" => {
            let allowed = foreign_kinds();
            let arr = v.as_array().ok_or("foreign_kinds must be a list of harness kind names")?;
            let mut want: Vec<&str> = Vec::new();
            for k in arr {
                let k = k.as_str().map(str::trim).ok_or("foreign_kinds must be a list of harness kind names")?;
                if !allowed.contains(&k) {
                    return Err(format!(
                        "'{k}' is not a foreign harness kind (one of {}; `noo` is always allowed and is not listed)",
                        allowed.join(", ")
                    ));
                }
                want.push(k);
            }
            // Name order, deduplicated (as the table writes them).
            Ok(json!(want.into_iter().collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>()))
        }
        _ => Err(format!("'{field}' is not a harness profile field (one of {})", FIELDS.join(", "))),
    }
}

/// Judge a per-node overrides object: any subset of [`FIELDS`] with valid
/// values. `null` is no overrides (`{}`). The result is normalised (trimmed
/// words, foreign kinds deduplicated in name order, [`CONTEXT_ALIAS`]
/// stored as `context`; `context` wins when both are given).
pub fn validate_overrides(v: &Value) -> Result<Value, String> {
    if v.is_null() {
        return Ok(json!({}));
    }
    let obj = v.as_object().ok_or("harness_profile must be an object of profile fields (or null to clear)")?;
    let mut out = Map::new();
    for (k, val) in obj {
        let checked = check_field(k, val)?;
        if k == CONTEXT_ALIAS {
            if !obj.contains_key("context") {
                out.insert("context".into(), checked);
            }
        } else {
            out.insert(k.clone(), checked);
        }
    }
    Ok(Value::Object(out))
}

/// One model name, with or without a trailing `:latest` (`llama3` and
/// `llama3:latest` are the same model).
fn same_model(a: &str, b: &str) -> bool {
    let n = |m: &str| m.trim().strip_suffix(":latest").unwrap_or(m.trim()).to_string();
    !a.trim().is_empty() && n(a) == n(b)
}

/// The measured first-byte wait, before the tier floor and the ceiling:
/// `ceil((load_secs + reference_prompt_tokens / prefill_tps) * headroom)`.
/// `None` for a bench that cannot be used (a speed of zero, a negative or
/// non-finite number).
pub fn measured_first_byte(rule: &MeasuredRule, bench: &ModelBench) -> Option<u64> {
    if !(bench.prefill_tps.is_finite() && bench.prefill_tps > 0.0) {
        return None;
    }
    if !(bench.load_secs.is_finite() && bench.load_secs >= 0.0) {
        return None;
    }
    let secs = ((bench.load_secs + rule.reference_prompt_tokens / bench.prefill_tps) * rule.headroom).ceil();
    (secs.is_finite() && secs >= 0.0).then_some(secs as u64)
}

/// Resolve a node's profile: per field, override > measured > tier
/// default. Pure.
///
/// `tier`: the node's derived tier (`None` or a tier the table does not
/// list → `unknown_tier`). `overrides`: the node's stored overrides (a
/// value that does not validate is ignored field by field: the tier
/// default stands). `bench`: the node record's `model_bench`.
/// `running_chat_model`: the node's chat model ([`running_chat_model`]:
/// its running chat placement's model, or the name its backend serves); a
/// bench of any other model (or no chat model) is not applied.
pub fn resolve(
    tier: Option<u8>,
    overrides: &Value,
    bench: Option<&ModelBench>,
    running_chat_model: Option<&str>,
) -> ResolvedProfile {
    resolve_with(table(), tier, overrides, bench, running_chat_model)
}

pub(crate) fn resolve_with(
    t: &Table,
    tier: Option<u8>,
    overrides: &Value,
    bench: Option<&ModelBench>,
    running_chat_model: Option<&str>,
) -> ResolvedProfile {
    let key = tier.map(|n| n.to_string()).filter(|k| t.tiers.contains_key(k)).unwrap_or_else(|| t.unknown_tier.clone());
    let d = t.tiers.get(&key).cloned().unwrap_or_else(|| {
        // The shipped table is held by a test to list its unknown_tier; a
        // malformed one falls back to the lowest-numbered row.
        t.tiers.values().next().cloned().expect("config/harness-profiles.json lists no tier")
    });
    let tier_num: u8 = key.parse().unwrap_or(0);
    let mut sources: BTreeMap<String, String> = FIELDS.iter().map(|f| (f.to_string(), "tier".to_string())).collect();
    let ov = |f: &str| overrides.get(f).and_then(|v| check_field(f, v).ok());

    // first_byte_secs: override > measured > tier.
    let mut first_byte = d.first_byte_secs;
    let applies = match (bench, running_chat_model) {
        (Some(b), Some(m)) => same_model(&b.model, m),
        _ => false,
    };
    if applies {
        if let Some(m) = bench.and_then(|b| measured_first_byte(&t.measured, b)) {
            first_byte = m.max(d.first_byte_secs).min(t.measured.max_first_byte_secs);
            sources.insert("first_byte_secs".into(), "measured".into());
        }
    }
    if let Some(v) = ov("first_byte_secs").and_then(|v| v.as_u64()) {
        first_byte = v;
        sources.insert("first_byte_secs".into(), "override".into());
    }

    let mut out = ResolvedProfile {
        tier: tier_num,
        first_byte_secs: first_byte,
        stream_idle_secs: d.stream_idle_secs,
        thinking: d.thinking.clone(),
        context: d.context,
        context_alias: d.context,
        claude_prompt: d.claude_prompt.clone(),
        foreign_kinds: d.foreign_kinds.clone(),
        sources: BTreeMap::new(),
        bench: bench.cloned(),
    };
    // The rest: override > tier (stated, never measured).
    if let Some(v) = ov("stream_idle_secs").and_then(|v| v.as_u64()) {
        out.stream_idle_secs = v;
        sources.insert("stream_idle_secs".into(), "override".into());
    }
    if let Some(v) = ov("thinking").and_then(|v| v.as_str().map(str::to_string)) {
        out.thinking = v;
        sources.insert("thinking".into(), "override".into());
    }
    // A row stored before the rename carries the old key.
    if let Some(v) = ov("context").or_else(|| ov(CONTEXT_ALIAS)).and_then(|v| v.as_u64()) {
        out.context = v;
        sources.insert("context".into(), "override".into());
    }
    out.context_alias = out.context;
    if let Some(v) = ov("claude_prompt").and_then(|v| v.as_str().map(str::to_string)) {
        out.claude_prompt = v;
        sources.insert("claude_prompt".into(), "override".into());
    }
    if let Some(v) = ov("foreign_kinds").and_then(|v| {
        v.as_array().map(|a| a.iter().filter_map(|k| k.as_str().map(str::to_string)).collect::<Vec<_>>())
    }) {
        out.foreign_kinds = v;
        sources.insert("foreign_kinds".into(), "override".into());
    }
    out.sources = sources;
    out
}

/// The node's chat model to compare a bench with, from its placements (as
/// `desired-config` lists them) and its record. The candidates: each
/// running `chat` placement's model as written (what the node agent benches
/// and names in `model_bench.model`) and the model the node reports for
/// that backend in `running_backends` (it can differ: an `auto` placement
/// resolved to a served name); with no chat placement, the model the node
/// reports for the bench's own backend (a backend adopted with no
/// placement). Either spelling counts: the candidate equal to
/// `bench_model` is returned, else the first. `None`: nothing to compare a
/// bench with.
pub fn running_chat_model(
    record: &Value,
    placements: &[Value],
    bench_backend: Option<&str>,
    bench_model: Option<&str>,
) -> Option<String> {
    let running = record.get("running_backends").and_then(|v| v.as_object());
    let usable = |m: &str| !m.trim().is_empty() && m.trim() != "auto";
    let mut candidates: Vec<String> = Vec::new();
    for p in placements {
        let role = p["role"].as_str().filter(|r| !r.is_empty()).unwrap_or("chat");
        if role != "chat" || p["desired_state"].as_str() != Some("running") {
            continue;
        }
        let Some(backend) = p["backend"].as_str() else { continue };
        if backend == "harness" {
            continue;
        }
        if let Some(m) = p["model"].as_str().filter(|m| usable(m)) {
            candidates.push(m.to_string());
        }
        if let Some(m) = running.and_then(|r| r.get(backend)).and_then(|v| v.as_str()).filter(|m| usable(m)) {
            candidates.push(m.to_string());
        }
    }
    if candidates.is_empty() {
        if let Some(m) = bench_backend
            .and_then(|b| running.and_then(|r| r.get(b)))
            .and_then(|v| v.as_str())
            .filter(|m| usable(m))
        {
            candidates.push(m.to_string());
        }
    }
    if let Some(want) = bench_model {
        if let Some(hit) = candidates.iter().find(|c| same_model(want, c)) {
            return Some(hit.clone());
        }
    }
    candidates.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bench(model: &str, load: f64, prefill: f64) -> ModelBench {
        ModelBench {
            model: model.into(),
            backend: Some("ollama".into()),
            load_secs: load,
            prefill_tps: prefill,
            decode_tps: Some(18.3),
            prompt_tokens: Some(8192),
            at: Some("2026-10-19T17:00:00Z".into()),
        }
    }

    #[test]
    fn the_shipped_table_parses_and_lists_every_field_for_every_tier() {
        let t = table();
        assert_eq!(t.fields, FIELDS.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "fields in declared order");
        assert_eq!(t.tiers.keys().cloned().collect::<Vec<_>>(), ["1", "2", "3", "4"]);
        assert!(t.tiers.contains_key(&t.unknown_tier), "unknown_tier names a listed tier");
        // Every field present in every row, in the raw JSON (serde would
        // reject a missing one; this names the row).
        let raw: Value = serde_json::from_str(RAW).unwrap();
        assert!(raw["_comment"].as_str().is_some_and(|c| c.len() > 40), "a real _comment");
        for (tier, row) in raw["tiers"].as_object().unwrap() {
            for f in FIELDS {
                assert!(row.get(f).is_some(), "tier {tier} has no {f}");
            }
            assert_eq!(row.as_object().unwrap().len(), FIELDS.len(), "tier {tier} has a field the list does not name");
        }
        assert!(t.measured.reference_prompt_tokens > 0.0 && t.measured.headroom >= 1.0);
    }

    #[test]
    fn every_tier_row_validates_as_an_override() {
        // The tier defaults obey the same rules an override does, so a value
        // the table ships is one an operator could also set.
        let raw: Value = serde_json::from_str(RAW).unwrap();
        for (tier, row) in raw["tiers"].as_object().unwrap() {
            let v = validate_overrides(row).unwrap_or_else(|e| panic!("tier {tier}: {e}"));
            assert_eq!(&v, row, "tier {tier} is already normalised (foreign kinds in name order)");
        }
    }

    #[test]
    fn tier_defaults_are_the_table_row_with_every_source_tier() {
        for n in 1u8..=4 {
            let r = resolve(Some(n), &json!({}), None, None);
            let d = &table().tiers[&n.to_string()];
            assert_eq!(r.tier, n);
            assert_eq!(
                (r.first_byte_secs, r.stream_idle_secs, r.thinking.as_str(), r.context, r.claude_prompt.as_str(), &r.foreign_kinds),
                (d.first_byte_secs, d.stream_idle_secs, d.thinking.as_str(), d.context, d.claude_prompt.as_str(), &d.foreign_kinds)
            );
            assert!(r.sources.values().all(|s| s == "tier"), "{:?}", r.sources);
            assert_eq!(r.sources.len(), FIELDS.len());
            assert!(r.bench.is_none());
        }
        let one = resolve(Some(1), &json!({}), None, None);
        assert_eq!((one.first_byte_secs, one.thinking.as_str(), one.claude_prompt.as_str()), (290, "auto", "full"));
    }

    #[test]
    fn an_unknown_or_underived_tier_reads_as_unknown_tier() {
        let three = resolve(Some(3), &json!({}), None, None);
        for t in [None, Some(0), Some(5), Some(9)] {
            let r = resolve(t, &json!({}), None, None);
            assert_eq!(r.tier, 3, "{t:?}");
            assert_eq!(r, three, "{t:?} resolves exactly as tier 3");
        }
    }

    #[test]
    fn an_override_beats_the_tier_default_field_by_field() {
        let r = resolve(Some(2), &json!({"thinking": "on", "context": 65536}), None, None);
        assert_eq!(r.thinking, "on");
        assert_eq!((r.context, r.context_alias), (65536, 65536));
        assert_eq!(r.sources["thinking"], "override");
        assert_eq!(r.sources["context"], "override");
        // A row stored before the rename (i226 decision 1) still applies.
        let old = resolve(Some(2), &json!({"ollama_context": 65536}), None, None);
        assert_eq!((old.context, old.context_alias, old.sources["context"].as_str()), (65536, 65536, "override"));
        assert_eq!(r.first_byte_secs, 600, "an untouched field keeps its tier default");
        assert_eq!(r.sources["first_byte_secs"], "tier");
        let all = resolve(
            Some(4),
            &json!({"first_byte_secs": 100, "stream_idle_secs": 120, "thinking": "auto", "context": 4096,
                    "claude_prompt": "full", "foreign_kinds": ["copilot"]}),
            None,
            None,
        );
        assert_eq!(
            (all.first_byte_secs, all.stream_idle_secs, all.thinking.as_str(), all.context, all.claude_prompt.as_str()),
            (100, 120, "auto", 4096, "full")
        );
        assert_eq!(all.foreign_kinds, ["copilot"]);
        assert!(all.sources.values().all(|s| s == "override"));
        // An override BELOW the tier default stands: the operator said so.
        assert_eq!(all.first_byte_secs, 100);
    }

    #[test]
    fn an_empty_foreign_kinds_override_offers_none() {
        let r = resolve(Some(1), &json!({"foreign_kinds": []}), None, None);
        assert!(r.foreign_kinds.is_empty());
        assert_eq!(r.sources["foreign_kinds"], "override");
    }

    #[test]
    fn an_override_beats_a_measured_value() {
        let b = bench("gemma4:12b", 4.2, 20.0);
        let r = resolve(Some(2), &json!({"first_byte_secs": 450}), Some(&b), Some("gemma4:12b"));
        assert_eq!(r.first_byte_secs, 450);
        assert_eq!(r.sources["first_byte_secs"], "override");
        assert_eq!(r.bench.as_ref(), Some(&b), "the bench still rides along");
    }

    #[test]
    fn the_measured_formula_raises_first_byte_above_the_tier_default() {
        // (4.2 + 30000 / 50) * 1.5 = 906.3 → 907, above tier 1's 290.
        let b = bench("gemma4:12b", 4.2, 50.0);
        assert_eq!(measured_first_byte(&table().measured, &b), Some(907));
        let r = resolve(Some(1), &json!({}), Some(&b), Some("gemma4:12b"));
        assert_eq!(r.first_byte_secs, 907);
        assert_eq!(r.sources["first_byte_secs"], "measured");
        // (2.0 + 30000 / 100) * 1.5 = 453 exactly: no rounding up.
        assert_eq!(measured_first_byte(&table().measured, &bench("m", 2.0, 100.0)), Some(453));
    }

    #[test]
    fn a_measured_value_never_drops_below_the_tier_default() {
        // (4.2 + 30000 / 210.5) * 1.5 = 220.08 → 221, below tier 2's 600.
        let b = bench("gemma4:12b", 4.2, 210.5);
        assert_eq!(measured_first_byte(&table().measured, &b), Some(221));
        let r = resolve(Some(2), &json!({}), Some(&b), Some("gemma4:12b"));
        assert_eq!(r.first_byte_secs, 600);
        assert_eq!(r.sources["first_byte_secs"], "measured", "the bench applied; the tier default is its floor");
    }

    #[test]
    fn a_measured_value_is_clamped_to_max_first_byte_secs() {
        // (4.2 + 30000 / 5) * 1.5 = 9006.3 → clamped to 1800.
        let b = bench("gemma4:12b", 4.2, 5.0);
        let r = resolve(Some(3), &json!({}), Some(&b), Some("gemma4:12b"));
        assert_eq!(r.first_byte_secs, table().measured.max_first_byte_secs);
        assert_eq!(r.first_byte_secs, 1800);
        assert_eq!(r.sources["first_byte_secs"], "measured");
    }

    #[test]
    fn measured_touches_first_byte_only() {
        let b = bench("gemma4:12b", 4.2, 5.0);
        let r = resolve(Some(2), &json!({}), Some(&b), Some("gemma4:12b"));
        let plain = resolve(Some(2), &json!({}), None, None);
        assert_eq!(
            (r.stream_idle_secs, &r.thinking, r.context, &r.claude_prompt, &r.foreign_kinds),
            (plain.stream_idle_secs, &plain.thinking, plain.context, &plain.claude_prompt, &plain.foreign_kinds)
        );
        for f in FIELDS.iter().filter(|f| **f != "first_byte_secs") {
            assert_eq!(r.sources[*f], "tier", "{f}");
        }
    }

    #[test]
    fn a_bench_of_a_different_model_is_ignored() {
        let b = bench("qwen3:8b", 4.2, 5.0);
        let r = resolve(Some(2), &json!({}), Some(&b), Some("gemma4:12b"));
        assert_eq!(r.first_byte_secs, 600);
        assert_eq!(r.sources["first_byte_secs"], "tier");
        assert_eq!(r.bench.as_ref(), Some(&b), "shown, not applied");
    }

    #[test]
    fn a_bench_with_no_running_chat_model_is_ignored() {
        let b = bench("gemma4:12b", 4.2, 5.0);
        let r = resolve(Some(2), &json!({}), Some(&b), None);
        assert_eq!((r.first_byte_secs, r.sources["first_byte_secs"].as_str()), (600, "tier"));
    }

    #[test]
    fn a_latest_tag_names_the_same_model() {
        let b = bench("gemma4:12b", 4.2, 50.0);
        let r = resolve(Some(1), &json!({}), Some(&b), Some("gemma4:12b:latest"));
        assert_eq!(r.sources["first_byte_secs"], "measured");
        let b = bench("llama3:latest", 4.2, 50.0);
        assert_eq!(resolve(Some(1), &json!({}), Some(&b), Some("llama3")).sources["first_byte_secs"], "measured");
    }

    #[test]
    fn an_unusable_bench_is_ignored() {
        for (load, prefill) in [(4.2, 0.0), (4.2, -3.0), (-1.0, 50.0), (f64::NAN, 50.0), (4.2, f64::INFINITY * 0.0)] {
            let b = bench("gemma4:12b", load, prefill);
            let r = resolve(Some(1), &json!({}), Some(&b), Some("gemma4:12b"));
            assert_eq!((r.first_byte_secs, r.sources["first_byte_secs"].as_str()), (290, "tier"), "{load} {prefill}");
        }
    }

    #[test]
    fn an_invalid_stored_override_is_ignored_not_applied() {
        let r = resolve(Some(2), &json!({"first_byte_secs": 0, "thinking": "maybe", "foreign_kinds": ["noo"], "bogus": 1}), None, None);
        assert_eq!(r, resolve(Some(2), &json!({}), None, None));
        let r = resolve(Some(2), &json!("not an object"), None, None);
        assert_eq!(r, resolve(Some(2), &json!({}), None, None));
    }

    #[test]
    fn validate_overrides_accepts_a_subset_and_normalises() {
        assert_eq!(validate_overrides(&Value::Null).unwrap(), json!({}));
        assert_eq!(validate_overrides(&json!({})).unwrap(), json!({}));
        assert_eq!(
            validate_overrides(&json!({"thinking": " on ", "foreign_kinds": ["copilot", "claude-code", "copilot"]})).unwrap(),
            json!({"thinking": "on", "foreign_kinds": ["claude-code", "copilot"]})
        );
        assert_eq!(validate_overrides(&json!({"first_byte_secs": 7200})).unwrap(), json!({"first_byte_secs": 7200}));
        assert_eq!(validate_overrides(&json!({"stream_idle_secs": 1})).unwrap(), json!({"stream_idle_secs": 1}));
        assert_eq!(validate_overrides(&json!({"context": 131072})).unwrap(), json!({"context": 131072}));
        // The old name is stored under the new one; the new one wins.
        assert_eq!(validate_overrides(&json!({"ollama_context": 131072})).unwrap(), json!({"context": 131072}));
        assert_eq!(validate_overrides(&json!({"ollama_context": 4096, "context": 8192})).unwrap(), json!({"context": 8192}));
        assert_eq!(validate_overrides(&json!({"foreign_kinds": []})).unwrap(), json!({"foreign_kinds": []}));
        assert_eq!(validate_overrides(&json!({"claude_prompt": "slim"})).unwrap(), json!({"claude_prompt": "slim"}));
    }

    #[test]
    fn validate_overrides_refuses_with_the_reason() {
        let e = |v: Value| validate_overrides(&v).unwrap_err();
        assert!(e(json!({"bogus": 1})).contains("not a harness profile field"));
        assert!(e(json!({"first_byte_secs": 0})).contains("1..=7200"));
        assert!(e(json!({"first_byte_secs": 7201})).contains("1..=7200"));
        assert!(e(json!({"stream_idle_secs": -5})).contains("stream_idle_secs"));
        assert!(e(json!({"stream_idle_secs": 2.5})).contains("whole number"));
        assert!(e(json!({"first_byte_secs": "300"})).contains("first_byte_secs"));
        assert!(e(json!({"context": 0})).contains("context must be"));
        assert!(e(json!({"ollama_context": 0})).contains("context must be"));
        assert!(e(json!({"thinking": "yes"})).contains("on, off or auto"));
        assert!(e(json!({"claude_prompt": "tiny"})).contains("full or slim"));
        assert!(e(json!({"foreign_kinds": ["noo"]})).contains("not a foreign harness kind"));
        assert!(e(json!({"foreign_kinds": ["nope"]})).contains("not a foreign harness kind"));
        assert!(e(json!({"foreign_kinds": "codex"})).contains("list"));
        assert!(e(json!([1, 2])).contains("object"));
    }

    #[test]
    fn the_resolved_profile_serialises_to_the_contract_shape() {
        let b = bench("gemma4:12b", 4.2, 210.5);
        let r = resolve(Some(2), &json!({"thinking": "off"}), Some(&b), Some("gemma4:12b"));
        let v = serde_json::to_value(&r).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        let mut want = vec!["tier", "sources", "bench", CONTEXT_ALIAS];
        want.extend(FIELDS);
        let mut have = keys.clone();
        have.sort();
        want.sort();
        assert_eq!(have, want);
        assert_eq!(v["tier"], 2);
        assert_eq!(v["first_byte_secs"], 600);
        assert_eq!(v["sources"], json!({"first_byte_secs": "measured", "stream_idle_secs": "tier", "thinking": "override",
            "context": "tier", "claude_prompt": "tier", "foreign_kinds": "tier"}));
        // Older node agents read only the old key: both are sent, equal.
        assert_eq!((v["context"].as_u64(), v[CONTEXT_ALIAS].as_u64()), (Some(32768), Some(32768)));
        assert_eq!(v["bench"]["model"], "gemma4:12b");
        assert_eq!(v["bench"]["prefill_tps"], 210.5);
        assert_eq!(v["foreign_kinds"], json!(["claude-code", "codex", "copilot"]));
        let none = serde_json::to_value(resolve(Some(2), &json!({}), None, None)).unwrap();
        assert!(none["bench"].is_null(), "no bench reads null");
    }

    #[test]
    fn model_bench_reads_off_the_record_or_not_at_all() {
        let rec = json!({"model_bench": {"model": "gemma4:12b", "backend": "ollama", "load_secs": 4.2, "prefill_tps": 210.5,
            "decode_tps": 18.3, "prompt_tokens": 8192, "at": "2026-10-19T17:00:00Z"}});
        let b = ModelBench::from_record(&rec).expect("parses");
        assert_eq!(b, bench("gemma4:12b", 4.2, 210.5));
        assert!(ModelBench::from_record(&json!({})).is_none());
        assert!(ModelBench::from_record(&json!({"model_bench": null})).is_none());
        assert!(ModelBench::from_record(&json!({"model_bench": {"model": "x"}})).is_none(), "no speeds, no bench");
    }

    #[test]
    fn the_chat_model_is_the_placement_model_or_the_served_name() {
        let rec = json!({"running_backends": {"ollama": "gemma4:12b-it-qat", "tei": "harrier"}});
        let placements = vec![
            json!({"backend": "tei", "role": "embed", "desired_state": "running", "model": "harrier"}),
            json!({"backend": "ollama", "role": "chat", "desired_state": "running", "model": "gemma4:12b"}),
        ];
        // The placement's model as written comes first (what the agent benches).
        assert_eq!(running_chat_model(&rec, &placements, None, None).as_deref(), Some("gemma4:12b"));
        assert_eq!(running_chat_model(&rec, &placements, None, Some("gemma4:12b")).as_deref(), Some("gemma4:12b"));
        // The served name counts too.
        assert_eq!(running_chat_model(&rec, &placements, None, Some("gemma4:12b-it-qat")).as_deref(), Some("gemma4:12b-it-qat"));
        // A bench of neither: the first candidate, which the bench does not match.
        assert_eq!(running_chat_model(&rec, &placements, None, Some("qwen3:8b")).as_deref(), Some("gemma4:12b"));
        // An `auto` placement: only the served name.
        let auto = vec![json!({"backend": "ollama", "role": "chat", "desired_state": "running", "model": "auto"})];
        assert_eq!(running_chat_model(&rec, &auto, None, None).as_deref(), Some("gemma4:12b-it-qat"));
        // A placement whose backend is not reported still names its model.
        let down = vec![json!({"backend": "vllm", "role": "chat", "desired_state": "running", "model": "m"})];
        assert_eq!(running_chat_model(&rec, &down, None, None).as_deref(), Some("m"));
        // Stopped: none, and a harness placement is not a chat model.
        let stopped = vec![json!({"backend": "ollama", "role": "chat", "desired_state": "stopped", "model": "x"})];
        assert_eq!(running_chat_model(&json!({}), &stopped, None, None), None);
        let harness = vec![json!({"backend": "harness", "role": "harness", "desired_state": "running", "model": "x"})];
        assert_eq!(running_chat_model(&json!({}), &harness, None, None), None);
        // An adopted backend with no placement: the bench's own backend.
        assert_eq!(running_chat_model(&rec, &[], Some("ollama"), None).as_deref(), Some("gemma4:12b-it-qat"));
        assert_eq!(running_chat_model(&json!({}), &[], Some("ollama"), None), None);
    }
}
