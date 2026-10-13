// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! LLM-based reranking — cross-encoder behaviour on the cluster's own chat model.
//!
//! Ported from `noomesh/pipeline/rerank.py` + `pipeline/llm.py`.
//! Serves `/api/external/rerank` when no node advertises the `rerank`
//! capability, so the contract holds with no dedicated reranker container.
//!
//! ## Why this port removes a round trip rather than moving one
//!
//! The Python path was: Rust → NATS → `worker.rerank.llm` → `llm_call` →
//! **HTTP POST back to the gateway's own `/v1/chat/completions`** → backend.
//! That loopback is the same shape the channels port deleted — a Python
//! handler whose main act is calling Rust again. Here the gateway resolves the
//! backend and calls it directly.
//!
//! ## Fidelity notes that are not obvious
//!
//! Two details are load-bearing and are ported deliberately, not incidentally:
//!
//! 1. **The response shape must be an OBJECT wrapping the array.** `json_mode`
//!    sets `response_format: {"type":"json_object"}`, which CONSTRAINS the model
//!    to emit an object. Asking for a bare array under that constraint produced
//!    `{"index":0,"score":1.0,"index":1,"score":0.0,...}` — and a JSON parser
//!    keeps only the last duplicate key, collapsing every score into one. The
//!    model was ranking correctly the whole time; the shape mismatch discarded
//!    the answer. The prompt therefore asks for `{"results":[...]}`.
//! 2. **Empty scores are a WARNING, not a silent identity fallback.** Identity
//!    order is indistinguishable from a real ranking at the API boundary, so
//!    this log is the only signal that reranking stopped happening.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::state::AppState;

/// Per-document truncation, to bound the prompt.
const MAX_DOC_CHARS: usize = 600;

const SYSTEM: &str = "You are a search-relevance judge. Score how well each document answers the \
query, from 0.0 (irrelevant) to 1.0 (perfectly relevant). Return ONLY a JSON \
object of the form {\"results\": [{\"index\": <int>, \"score\": <float>}, ...]} \
with exactly one entry per document, and no prose.";

fn build_prompt(query: &str, docs: &[String]) -> String {
    let mut lines = vec![format!("Query: {query}"), String::new(), "Documents:".to_string()];
    for (i, d) in docs.iter().enumerate() {
        let flat = d.replace('\n', " ");
        let snippet: String = flat.trim().chars().take(MAX_DOC_CHARS).collect();
        lines.push(format!("[{i}] {snippet}"));
    }
    lines.push(String::new());
    lines.push(
        "Return {\"results\": [...]} with one {\"index\",\"score\"} entry per document.".to_string(),
    );
    lines.join("\n")
}

/// Turn the model's JSON into a length-n score vector clamped to [0,1].
///
/// Accepts `{"results":[...]}`, `{"scores":[...]}`, a bare array, or an object
/// whose first array-valued field is the list — matching the Python parser's
/// tolerance, because model output shape varies by backend.
pub fn parse_scores(raw: &Value, n: usize) -> Vec<f64> {
    let mut scores = vec![0.0; n];
    let items = match raw {
        Value::Array(_) => Some(raw),
        Value::Object(map) => map
            .get("results")
            .or_else(|| map.get("scores"))
            .or_else(|| map.values().find(|v| v.is_array())),
        _ => None,
    };
    let Some(Value::Array(items)) = items else {
        return scores;
    };
    for obj in items {
        let (Some(idx), Some(sc)) = (
            obj.get("index").and_then(value_as_i64),
            obj.get("score").and_then(value_as_f64),
        ) else {
            continue;
        };
        if idx >= 0 && (idx as usize) < n {
            scores[idx as usize] = sc.clamp(0.0, 1.0);
        }
    }
    scores
}

/// Accept numeric-or-string, as some backends quote their numbers.
fn value_as_i64(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_f64().map(|f| f as i64))
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn value_as_f64(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_i64().map(|i| i as f64))
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Fallback ranking: original order, descending positional scores.
pub fn identity(n: usize) -> Vec<Value> {
    (0..n)
        .map(|i| {
            let score = 1.0 - (i as f64) / (n.max(1) as f64);
            json!({"index": i, "score": round4(score)})
        })
        .collect()
}

fn round4(v: f64) -> f64 {
    (v * 10_000.0).round() / 10_000.0
}

/// Extract a JSON object from a model response that may be fenced or padded.
///
/// Models wrap JSON in ```json fences or add prose despite instructions; the
/// Python side had a repair path for the same reason.
pub fn extract_json(content: &str) -> Option<Value> {
    let text = content.trim();
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return Some(v);
    }
    // Strip a fenced block if present.
    let inner = text
        .strip_prefix("```json")
        .or_else(|| text.strip_prefix("```"))
        .map(|s| s.trim_start_matches('\n'))
        .and_then(|s| s.strip_suffix("```").or(Some(s)))
        .unwrap_or(text);
    if let Ok(v) = serde_json::from_str::<Value>(inner.trim()) {
        return Some(v);
    }
    // Last resort: the outermost {...} span.
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end > start {
        serde_json::from_str(&text[start..=end]).ok()
    } else {
        None
    }
}

/// Rank `documents` against `query`. Never returns an error — degrades to
/// identity order, matching the Python contract ("never returns empty").
pub async fn rerank(
    state: &Arc<AppState>,
    query: &str,
    documents: &[String],
    top_n: Option<usize>,
) -> Vec<Value> {
    let n = documents.len();
    if n == 0 {
        return Vec::new();
    }

    let mut results = match call_model(state, query, documents, n).await {
        Some(raw) => {
            let scores = parse_scores(&raw, n);
            if scores.iter().all(|s| *s == 0.0) {
                // WARN, not debug: identity order is indistinguishable from a
                // real ranking at the API boundary, so this is the only signal
                // that reranking silently stopped happening. Carry the raw
                // shape — the duplicate-key bug was invisible without it.
                let shape = raw.to_string().chars().take(200).collect::<String>();
                tracing::warn!(n, raw = %shape, "llm_rerank.empty_scores");
                identity(n)
            } else {
                scores
                    .iter()
                    .enumerate()
                    .map(|(i, s)| json!({"index": i, "score": round4(*s)}))
                    .collect()
            }
        }
        None => identity(n),
    };

    results.sort_by(|a, b| {
        let sa = a.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let sb = b.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });
    match top_n {
        Some(k) => results.into_iter().take(k).collect(),
        None => results,
    }
}

/// One narrow completion against the resolved backend.
///
/// Direct, not through the gateway's own HTTP surface: the Python path POSTed
/// to `{gateway}/v1/chat/completions`, i.e. looped back into this process.
async fn call_model(
    state: &Arc<AppState>,
    query: &str,
    docs: &[String],
    n: usize,
) -> Option<Value> {
    let backend = match crate::coordinator::resolve_backend(state).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, n, "llm_rerank.no_backend");
            return None;
        }
    };

    let body = json!({
        "model": backend.model,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": build_prompt(query, docs)},
        ],
        "temperature": 0.0,
        // Same budget rule as Python: ~40 tokens per scored document plus
        // headroom, capped so a large candidate set cannot run away.
        "max_tokens": std::cmp::min(2048, 40 * n + 64),
        "stream": false,
        "response_format": {"type": "json_object"},
    });

    let url = format!("{}/v1/chat/completions", backend.url.trim_end_matches('/'));
    let client = crate::tls::cluster_client();
    let resp = match client
        .post(&url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!(status = %r.status(), n, "llm_rerank.non_2xx");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, n, "llm_rerank.request_failed");
            return None;
        }
    };

    let data: Value = resp.json().await.ok()?;
    let content = data
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or("");
    extract_json(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_results_object_shape() {
        let raw = json!({"results": [{"index": 0, "score": 0.9}, {"index": 1, "score": 0.2}]});
        assert_eq!(parse_scores(&raw, 2), vec![0.9, 0.2]);
    }

    #[test]
    fn parses_a_bare_array_and_a_scores_key() {
        let arr = json!([{"index": 1, "score": 0.5}]);
        assert_eq!(parse_scores(&arr, 2), vec![0.0, 0.5]);
        let scored = json!({"scores": [{"index": 0, "score": 1.0}]});
        assert_eq!(parse_scores(&scored, 1), vec![1.0]);
    }

    #[test]
    fn clamps_and_ignores_out_of_range_indices() {
        let raw = json!({"results": [
            {"index": 0, "score": 5.0},     // clamps to 1.0
            {"index": 1, "score": -3.0},    // clamps to 0.0
            {"index": 99, "score": 1.0},    // out of range, ignored
        ]});
        assert_eq!(parse_scores(&raw, 2), vec![1.0, 0.0]);
    }

    #[test]
    fn tolerates_quoted_numbers() {
        // Some backends emit strings for numbers; the Python parser coerced
        // via int()/float(), so this must too or every score reads 0.
        let raw = json!({"results": [{"index": "0", "score": "0.75"}]});
        assert_eq!(parse_scores(&raw, 1), vec![0.75]);
    }

    #[test]
    fn malformed_entries_default_to_zero() {
        let raw = json!({"results": [{"index": 0}, "junk", {"score": 0.5}]});
        assert_eq!(parse_scores(&raw, 2), vec![0.0, 0.0]);
        assert_eq!(parse_scores(&json!("nonsense"), 2), vec![0.0, 0.0]);
    }

    #[test]
    fn identity_is_descending_and_bounded() {
        let ids = identity(3);
        let scores: Vec<f64> = ids.iter().map(|r| r["score"].as_f64().unwrap()).collect();
        assert!(scores[0] > scores[1] && scores[1] > scores[2]);
        assert!(scores.iter().all(|s| (0.0..=1.0).contains(s)));
        assert_eq!(ids[0]["index"], 0);
    }

    #[test]
    fn extracts_json_from_fenced_or_padded_output() {
        assert!(extract_json("{\"results\":[]}").is_some());
        assert!(extract_json("```json\n{\"results\":[]}\n```").is_some());
        assert!(extract_json("Here you go: {\"results\":[]} — done").is_some());
        assert!(extract_json("no json here").is_none());
    }

    #[test]
    fn prompt_truncates_documents_and_numbers_them() {
        let long = "x".repeat(MAX_DOC_CHARS + 200);
        let p = build_prompt("q", &[long, "second\nline".to_string()]);
        assert!(p.contains("[0] "));
        assert!(p.contains("[1] second line"), "newlines must be flattened");
        // The oversized doc must be cut to the cap.
        let longest = p.lines().find(|l| l.starts_with("[0] ")).unwrap();
        assert!(longest.len() <= MAX_DOC_CHARS + 8);
    }

    #[test]
    fn duplicate_key_shape_is_why_we_ask_for_an_object() {
        // Regression guard for the real bug: under json_object constraint a
        // bare-array request produced duplicate keys, and a parser keeps only
        // the last — collapsing every score into one entry.
        let collapsed: Value = serde_json::from_str(
            r#"{"index":0,"score":1.0,"index":1,"score":0.0}"#,
        )
        .unwrap();
        // Parsed as a flat object, this yields NO usable per-doc scores...
        assert_eq!(parse_scores(&collapsed, 2), vec![0.0, 0.0]);
        // ...whereas the shape we actually request does.
        let proper = json!({"results": [{"index":0,"score":1.0},{"index":1,"score":0.0}]});
        assert_eq!(parse_scores(&proper, 2), vec![1.0, 0.0]);
    }
}
