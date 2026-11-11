// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC
//! vLLM's own metrics (prefix-cache hits, queue depth, time to first token),
//! fetched by the gateway and re-exported on its `/metrics`.
//!
//! Prometheus scrapes only controller-local targets, and a backend door admits
//! only its node's agent and the controller's services (`doorCallers`), so
//! nothing collected a placed vLLM's metrics. The gateway already reaches every
//! node's agent, and the agent already reaches its doors: every
//! [`INTERVAL_SECS`] this loop asks each placed vLLM's agent for the backend's
//! `/metrics` (`GET /backend-metrics/<backend>`, node-agent-go's
//! handleBackendMetrics), keeps only [`ALLOWED_FAMILIES`], and the gateway's own
//! `/metrics` serves them. No new trust path and no new scrape target
//! (operator decision 2026-11-11, option A).
//!
//! The upstream text is a backend's output, so it is handled as untrusted:
//! the body is bounded in size ([`MAX_BODY`]) and time ([`FETCH_TIMEOUT`]),
//! every line is parsed defensively (an unparsable line is dropped, never
//! guessed at), the number of samples is capped, and the `node` and `backend`
//! labels come from the gateway's own placement record, never from the scraped
//! text (a scraped `node`/`backend` label is dropped). A failed fetch sets
//! `noo_backend_metrics_up{node,backend} 0` and keeps NO samples for that
//! target, so a dead backend never shows its last good values.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::http::Method;

use crate::state::AppState;

pub const LOOP_NAME: &str = "backend_metrics";
pub const INTERVAL_SECS: u64 = 15;
const STARTUP_GRACE_SECS: u64 = 30;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// A vLLM `/metrics` page is tens of KiB; this is a ceiling, not a target.
pub const MAX_BODY: usize = 2 << 20;
/// Per target, after the allow-list (histogram buckets × models).
pub const MAX_SAMPLES_PER_TARGET: usize = 4000;

/// Placed backends whose `/metrics` is vLLM's exposition.
pub const METRICS_BACKENDS: &[&str] = &["vllm", "vllm-secondary"];

/// The metric families kept. Everything else the backend reports is dropped.
pub const ALLOWED_FAMILIES: &[&str] = &[
    "vllm:prefix_cache_queries",
    "vllm:prefix_cache_hits",
    "vllm:num_requests_waiting",
    "vllm:num_requests_running",
    "vllm:time_to_first_token_seconds",
    "vllm:e2e_request_latency_seconds",
    "vllm:gpu_cache_usage_perc",
    "vllm:kv_cache_usage_perc",
    "vllm:prompt_tokens",
    "vllm:generation_tokens",
];

/// The sample-name suffixes a family's series may carry (counters, histograms).
const SUFFIXES: &[&str] = &["", "_total", "_bucket", "_sum", "_count"];

/// Labels only the gateway may set.
const RESERVED_LABELS: &[&str] = &["node", "backend"];

#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub family: &'static str,
    pub name: String,
    pub labels: Vec<(String, String)>,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TargetScrape {
    pub node: String,
    pub backend: String,
    pub up: bool,
    pub samples: Vec<Sample>,
    pub types: BTreeMap<&'static str, &'static str>,
}

static SNAPSHOT: RwLock<Vec<TargetScrape>> = RwLock::new(Vec::new());

/// The allowed family a sample name belongs to, if any.
pub fn family_of(name: &str) -> Option<&'static str> {
    ALLOWED_FAMILIES
        .iter()
        .copied()
        .find(|f| SUFFIXES.iter().any(|s| name.strip_prefix(f).is_some_and(|rest| rest == *s)))
}

fn label_name_ok(n: &str) -> bool {
    let mut c = n.chars();
    matches!(c.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
        && c.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && n.len() <= 64
}

fn value_ok(v: &str) -> bool {
    matches!(v, "+Inf" | "-Inf" | "NaN") || v.parse::<f64>().is_ok_and(|x| x.is_finite())
}

/// `{a="x",b="y\"z"}` → pairs; `None` on anything malformed.
fn parse_labels(s: &str) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut rest = s.trim();
    while !rest.is_empty() {
        let eq = rest.find('=')?;
        let name = rest[..eq].trim();
        if !label_name_ok(name) {
            return None;
        }
        let after = rest[eq + 1..].trim_start();
        let mut chars = after.char_indices();
        if chars.next()?.1 != '"' {
            return None;
        }
        let mut value = String::new();
        let mut end = None;
        let mut escaped = false;
        for (i, ch) in chars {
            if escaped {
                value.push(match ch {
                    'n' => '\n',
                    other => other,
                });
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                end = Some(i);
                break;
            } else {
                value.push(ch);
            }
            if value.len() > 256 {
                return None;
            }
        }
        let end = end?;
        out.push((name.to_string(), value));
        rest = after[end + 1..].trim_start();
        if let Some(r) = rest.strip_prefix(',') {
            rest = r.trim_start();
        } else if !rest.is_empty() {
            return None;
        }
    }
    Some(out)
}

/// One exposition line → a kept sample, or `None` (comment, unlisted family,
/// or malformed). Reserved labels are dropped here.
fn parse_sample(line: &str) -> Option<Sample> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (name, labels, tail) = match line.find('{') {
        Some(open) => {
            let close = line[open..].rfind('}')? + open;
            (&line[..open], parse_labels(&line[open + 1..close])?, &line[close + 1..])
        }
        None => {
            let sp = line.find(char::is_whitespace)?;
            (&line[..sp], Vec::new(), &line[sp..])
        }
    };
    let family = family_of(name)?;
    // The value, then an optional timestamp, which is dropped.
    let value = tail.split_whitespace().next()?;
    if !value_ok(value) {
        return None;
    }
    let labels = labels.into_iter().filter(|(k, _)| !RESERVED_LABELS.contains(&k.as_str())).collect();
    Some(Sample { family, name: name.to_string(), labels, value: value.to_string() })
}

/// The `# TYPE` of an allowed family, if the line is one.
fn parse_type(line: &str) -> Option<(&'static str, &'static str)> {
    let mut it = line.strip_prefix("# TYPE ")?.split_whitespace();
    let name = it.next()?;
    let family = ALLOWED_FAMILIES.iter().copied().find(|f| *f == name)?;
    let ty = match it.next()? {
        "counter" => "counter",
        "gauge" => "gauge",
        "histogram" => "histogram",
        "summary" => "summary",
        "untyped" => "untyped",
        _ => return None,
    };
    Some((family, ty))
}

/// Parse a backend's `/metrics` text: only allowed families, capped.
pub fn parse(text: &str) -> (Vec<Sample>, BTreeMap<&'static str, &'static str>) {
    let mut samples = Vec::new();
    let mut types = BTreeMap::new();
    for line in text.lines() {
        if let Some((f, t)) = parse_type(line) {
            types.entry(f).or_insert(t);
        } else if let Some(s) = parse_sample(line) {
            if samples.len() >= MAX_SAMPLES_PER_TARGET {
                break;
            }
            samples.push(s);
        }
    }
    (samples, types)
}

fn esc(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// The exposition the gateway serves for a snapshot.
pub fn render(snap: &[TargetScrape]) -> String {
    let mut out = String::new();
    if snap.is_empty() {
        return out;
    }
    out.push_str("# TYPE noo_backend_metrics_up gauge\n");
    for t in snap {
        out.push_str(&format!(
            "noo_backend_metrics_up{{node=\"{}\",backend=\"{}\"}} {}\n",
            esc(&t.node),
            esc(&t.backend),
            u8::from(t.up)
        ));
    }
    for family in ALLOWED_FAMILIES {
        let mut typed = false;
        for t in snap {
            for s in t.samples.iter().filter(|s| s.family == *family) {
                if !typed {
                    if let Some(ty) = snap.iter().find_map(|t| t.types.get(family)) {
                        out.push_str(&format!("# TYPE {family} {ty}\n"));
                    }
                    typed = true;
                }
                let mut labels = format!("node=\"{}\",backend=\"{}\"", esc(&t.node), esc(&t.backend));
                for (k, v) in &s.labels {
                    labels.push_str(&format!(",{k}=\"{}\"", esc(v)));
                }
                out.push_str(&format!("{}{{{labels}}} {}\n", s.name, s.value));
            }
        }
    }
    out
}

/// What the gateway's `/metrics` appends.
pub fn metrics_text() -> String {
    render(&SNAPSHOT.read().unwrap_or_else(|e| e.into_inner()))
}

/// Fetch one target's text, bounded in time and size.
async fn fetch(state: &AppState, node: &str, backend: &str) -> anyhow::Result<String> {
    let link = crate::node_link::NodeLink::for_node(state, node).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut resp = link
        .request(Method::GET, &format!("/backend-metrics/{backend}"))
        .timeout(FETCH_TIMEOUT)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("agent answered {}", resp.status());
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > MAX_BODY {
            anyhow::bail!("metrics body over {MAX_BODY} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// The (node, backend) pairs to scrape: the placement record's running vLLMs.
pub fn targets(placements: &[(String, String, Option<String>, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = placements
        .iter()
        .filter(|(_, b, _, _)| METRICS_BACKENDS.contains(&b.as_str()))
        .map(|(n, b, _, _)| (n.clone(), b.clone()))
        .collect();
    out.sort();
    out.dedup();
    out
}

pub async fn run_once(state: &AppState) -> anyhow::Result<()> {
    let placements = crate::coordinator::classes::load_placements(&state.db).await?;
    let mut snap = Vec::new();
    for (node, backend) in targets(&placements) {
        let scrape = match tokio::time::timeout(FETCH_TIMEOUT + Duration::from_secs(1), fetch(state, &node, &backend)).await {
            Ok(Ok(text)) => {
                let (samples, types) = parse(&text);
                TargetScrape { node, backend, up: true, samples, types }
            }
            Ok(Err(e)) => {
                tracing::debug!(node = %node, backend = %backend, error = %e, "backend metrics fetch failed");
                TargetScrape { node, backend, up: false, samples: Vec::new(), types: BTreeMap::new() }
            }
            Err(_) => TargetScrape { node, backend, up: false, samples: Vec::new(), types: BTreeMap::new() },
        };
        snap.push(scrape);
    }
    // Replaced whole: a target no longer placed disappears, a failed one
    // keeps no samples.
    *SNAPSHOT.write().unwrap_or_else(|e| e.into_inner()) = snap;
    Ok(())
}

pub fn spawn(state: Arc<AppState>) {
    crate::managed_loop::ManagedLoop::new(LOOP_NAME, INTERVAL_SECS)
        .startup_grace(STARTUP_GRACE_SECS)
        .spawn(state, |state| async move { run_once(&state).await });
}

#[cfg(test)]
mod tests {
    use super::*;

    const VLLM: &str = r#"# HELP vllm:num_requests_waiting Number of requests waiting.
# TYPE vllm:num_requests_waiting gauge
vllm:num_requests_waiting{engine="0",model_name="google/gemma"} 3.0
# TYPE vllm:prefix_cache_hits counter
vllm:prefix_cache_hits_total{engine="0",model_name="google/gemma"} 1234.0
# TYPE vllm:time_to_first_token_seconds histogram
vllm:time_to_first_token_seconds_bucket{engine="0",le="0.5",model_name="google/gemma"} 10.0
vllm:time_to_first_token_seconds_bucket{engine="0",le="+Inf",model_name="google/gemma"} 12.0
vllm:time_to_first_token_seconds_sum{engine="0",model_name="google/gemma"} 4.2
vllm:time_to_first_token_seconds_count{engine="0",model_name="google/gemma"} 12.0
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 1.2e9
vllm:num_preemptions_total{engine="0"} 7.0
python_gc_objects_collected_total{generation="0"} 100.0
"#;

    #[test]
    fn only_the_allowed_families_are_kept() {
        let (samples, types) = parse(VLLM);
        let names: Vec<&str> = samples.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"vllm:num_requests_waiting"));
        assert!(names.contains(&"vllm:prefix_cache_hits_total"));
        assert!(names.contains(&"vllm:time_to_first_token_seconds_bucket"));
        assert!(names.contains(&"vllm:time_to_first_token_seconds_count"));
        for unlisted in ["process_resident_memory_bytes", "vllm:num_preemptions_total", "python_gc_objects_collected_total"] {
            assert!(!names.contains(&unlisted), "{unlisted} is not on the allow-list and must be dropped");
        }
        assert_eq!(types.get("vllm:time_to_first_token_seconds"), Some(&"histogram"));
        assert!(!types.contains_key("process_resident_memory_bytes"));
    }

    #[test]
    fn a_family_name_prefix_is_not_a_family() {
        assert_eq!(family_of("vllm:num_requests_waiting"), Some("vllm:num_requests_waiting"));
        assert_eq!(family_of("vllm:num_requests_waiting_extra"), None);
        assert_eq!(family_of("vllm:prefix_cache_hits_total"), Some("vllm:prefix_cache_hits"));
        assert_eq!(family_of("vllm:prefix_cache_hitsX"), None);
    }

    /// The backend's text cannot set the labels the gateway owns, and the
    /// gateway's values come from its placement record.
    #[test]
    fn scraped_node_and_backend_labels_are_dropped() {
        let text = "vllm:num_requests_waiting{node=\"evil\",backend=\"spoof\",engine=\"0\"} 1\n";
        let (samples, _) = parse(text);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].labels, vec![("engine".to_string(), "0".to_string())]);
        let snap = vec![TargetScrape { node: "awolf".into(), backend: "vllm".into(), up: true, samples, types: BTreeMap::new() }];
        let out = render(&snap);
        assert!(out.contains("vllm:num_requests_waiting{node=\"awolf\",backend=\"vllm\",engine=\"0\"} 1\n"), "{out}");
        assert!(!out.contains("evil") && !out.contains("spoof"), "{out}");
    }

    #[test]
    fn malformed_lines_are_dropped_not_guessed() {
        for bad in [
            "vllm:num_requests_waiting{engine=\"0\" 1",           // unclosed
            "vllm:num_requests_waiting{engine=0} 1",              // unquoted
            "vllm:num_requests_waiting{1bad=\"x\"} 1",            // label name
            "vllm:num_requests_waiting{engine=\"0\"} notanumber", // value
            "vllm:num_requests_waiting{engine=\"0\"} 1e999",      // overflow
            "vllm:num_requests_waiting",                          // no value
            "vllm:num_requests_waiting{a=\"x\" b=\"y\"} 1",       // no comma
        ] {
            assert!(parse(bad).0.is_empty(), "kept a malformed line: {bad}");
        }
        assert_eq!(parse("vllm:num_requests_waiting{a=\"q\\\"x\"} +Inf 1700000000\n").0[0].value, "+Inf");
    }

    #[test]
    fn samples_are_capped_per_target() {
        let line = "vllm:num_requests_waiting{engine=\"0\"} 1\n";
        let (samples, _) = parse(&line.repeat(MAX_SAMPLES_PER_TARGET + 50));
        assert_eq!(samples.len(), MAX_SAMPLES_PER_TARGET);
    }

    /// A failed fetch is `up 0` with no samples: never the last good values.
    #[test]
    fn a_down_target_reports_up_zero_and_no_values() {
        let snap = vec![
            TargetScrape { node: "awolf".into(), backend: "vllm".into(), up: false, samples: Vec::new(), types: BTreeMap::new() },
            TargetScrape { node: "pop-os".into(), backend: "vllm".into(), up: true, samples: parse(VLLM).0, types: parse(VLLM).1 },
        ];
        let out = render(&snap);
        assert!(out.contains("noo_backend_metrics_up{node=\"awolf\",backend=\"vllm\"} 0\n"), "{out}");
        assert!(out.contains("noo_backend_metrics_up{node=\"pop-os\",backend=\"vllm\"} 1\n"), "{out}");
        assert!(!out.lines().any(|l| l.starts_with("vllm:") && l.contains("node=\"awolf\"")), "{out}");
        assert_eq!(out.matches("# TYPE vllm:time_to_first_token_seconds histogram").count(), 1);
    }

    #[test]
    fn targets_are_the_placed_vllms_only() {
        let rows = vec![
            ("awolf".to_string(), "vllm".to_string(), None, "chat".to_string()),
            ("awolf".to_string(), "vllm".to_string(), None, "chat".to_string()),
            ("mcmini".to_string(), "ollama".to_string(), None, "chat".to_string()),
            ("pop-os".to_string(), "vllm-secondary".to_string(), None, "chat".to_string()),
        ];
        assert_eq!(targets(&rows), vec![("awolf".into(), "vllm".into()), ("pop-os".into(), "vllm-secondary".into())]);
    }

    #[test]
    fn nothing_placed_renders_nothing() {
        assert_eq!(render(&[]), "");
    }
}
