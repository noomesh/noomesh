// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Prometheus metrics — in-process counters/gauges + DB-backed gauges.
//!
//! The Rust gateway is the canonical scrape target. Increments from
//! still-Python ML modules (temporal extractor, embedding worker, add-on
//! sidecars, query embedding cache) arrive over NATS on the
//! `metrics.>` subject and land in the same atomic counters.
//!
//! Why hand-rolled rather than the `prometheus` or `metrics` crates:
//! the metric set is small (~15 entries), label cardinality is bounded
//! (kind, author, layer enums), and we want zero new compile-time
//! dependencies. The text format is trivial to emit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-process counter & gauge registry. One instance lives on AppState.
#[derive(Default)]
pub struct MetricsState {
    /// Cumulative event counters. Key = "name{sorted_labels}".
    counters: RwLock<HashMap<String, Arc<AtomicU64>>>,
    /// Point-in-time gauges. Key = "name{sorted_labels}".
    gauges: RwLock<HashMap<String, Arc<AtomicU64>>>,
}

impl MetricsState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment a counter by `value` (default 1). Creates the entry if absent.
    pub async fn inc_counter(
        &self,
        name: &str,
        labels: Option<&HashMap<String, String>>,
        value: u64,
    ) {
        let key = format_key(name, labels);
        let cell = self.get_or_insert(&self.counters, &key).await;
        cell.fetch_add(value, Ordering::Relaxed);
    }

    /// Set a gauge to `value`. Stored as bits of f64 (we treat gauges as
    /// floats logically; atomic storage is u64-shaped).
    pub async fn set_gauge(
        &self,
        name: &str,
        labels: Option<&HashMap<String, String>>,
        value: f64,
    ) {
        let key = format_key(name, labels);
        let cell = self.get_or_insert(&self.gauges, &key).await;
        cell.store(value.to_bits(), Ordering::Relaxed);
    }

    async fn get_or_insert(
        &self,
        map: &RwLock<HashMap<String, Arc<AtomicU64>>>,
        key: &str,
    ) -> Arc<AtomicU64> {
        if let Some(cell) = map.read().await.get(key) {
            return cell.clone();
        }
        let mut w = map.write().await;
        w.entry(key.to_string())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .clone()
    }

    /// Render the registry in Prometheus exposition format.
    pub async fn render(&self) -> String {
        let mut out = String::with_capacity(4096);
        let counters = self.counters.read().await;
        let gauges = self.gauges.read().await;

        // Group by metric name to emit HELP/TYPE once per family.
        let mut by_name_counter: HashMap<&str, Vec<(&String, u64)>> = HashMap::new();
        for (key, cell) in counters.iter() {
            let name = name_part(key);
            by_name_counter
                .entry(name)
                .or_default()
                .push((key, cell.load(Ordering::Relaxed)));
        }
        let mut names: Vec<&&str> = by_name_counter.keys().collect();
        names.sort();
        for name in names {
            out.push_str(&format!("# TYPE {} counter\n", name));
            let mut entries = by_name_counter[name].clone();
            entries.sort_by_key(|(k, _)| (*k).clone());
            for (key, value) in entries {
                out.push_str(&format!("{} {}\n", key, value));
            }
        }

        let mut by_name_gauge: HashMap<&str, Vec<(&String, f64)>> = HashMap::new();
        for (key, cell) in gauges.iter() {
            let name = name_part(key);
            by_name_gauge
                .entry(name)
                .or_default()
                .push((key, f64::from_bits(cell.load(Ordering::Relaxed))));
        }
        let mut names: Vec<&&str> = by_name_gauge.keys().collect();
        names.sort();
        for name in names {
            out.push_str(&format!("# TYPE {} gauge\n", name));
            let mut entries = by_name_gauge[name].clone();
            entries.sort_by_key(|(k, _)| (*k).clone());
            for (key, value) in entries {
                out.push_str(&format!("{} {}\n", key, value));
            }
        }

        out
    }
}

fn format_key(name: &str, labels: Option<&HashMap<String, String>>) -> String {
    match labels {
        None => name.to_string(),
        Some(map) if map.is_empty() => name.to_string(),
        Some(map) => {
            let mut kvs: Vec<(&String, &String)> = map.iter().collect();
            kvs.sort_by_key(|(k, _)| (*k).clone());
            let inner: Vec<String> = kvs
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, escape_label(v)))
                .collect();
            format!("{}{{{}}}", name, inner.join(","))
        }
    }
}

fn name_part(key: &str) -> &str {
    match key.find('{') {
        Some(i) => &key[..i],
        None => key,
    }
}

// ───────────────────────────────────────────────────────────────────
// Add-on counters: the one door an add-on's metrics enter by.
// ───────────────────────────────────────────────────────────────────

/// Every add-on counter is rendered under this prefix, so an add-on can
/// neither collide with nor inflate a series the gateway owns
/// (`noo_auth_failures_5m`, the cluster gauges, …).
pub const ADDON_COUNTER_PREFIX: &str = "noo_addon_";
/// The label naming who incremented it. Set by the gateway from the
/// credential, never from the body, so it cannot be spoofed or omitted.
pub const ADDON_SOURCE_LABEL: &str = "addon";
/// Distinct series one source may create. A counter with an unbounded label
/// (a request id, a timestamp) would otherwise grow the scrape without limit;
/// past the cap, NEW series are refused and existing ones keep counting.
pub const ADDON_SERIES_CAP: usize = 256;
const ADDON_MAX_LABELS: usize = 4;
const ADDON_MAX_LABEL_VALUE: usize = 64;
const ADDON_MAX_INCREMENT: f64 = 1_000_000.0;

fn is_metric_word(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Who a counter is attributed to, from the credential that sent it: the
/// consumer of an exchanged add-on token (`addon:svc:evolve` → `evolve`) or a
/// stack service's cluster actor (`pai-evolve` → `evolve`), so one add-on is
/// one source whichever credential it holds this week.
pub fn addon_source(actor: &str) -> String {
    let a = actor.strip_prefix("addon:").unwrap_or(actor);
    let a = a.strip_prefix("svc:").unwrap_or(a);
    let a = a.strip_prefix("pai-").or_else(|| a.strip_prefix("noo-")).unwrap_or(a);
    a.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' })
        .take(ADDON_MAX_LABEL_VALUE)
        .collect()
}

/// Why an add-on increment is refused, or `None` when it is well-formed:
/// a `_total` counter name, at most four plain labels (none of them the
/// source label), short values, and a positive whole increment.
pub fn addon_counter_refusal(name: &str, labels: &HashMap<String, String>, value: f64) -> Option<String> {
    if !is_metric_word(name, 80) || !name.ends_with("_total") {
        return Some(format!("counter name {name:?} must be lowercase snake_case ending in _total"));
    }
    if let Some(why) = addon_labels_refusal(labels) {
        return Some(why);
    }
    if !((1.0..=ADDON_MAX_INCREMENT).contains(&value) && value.fract() == 0.0) {
        return Some(format!("value must be a whole number from 1 to {ADDON_MAX_INCREMENT}"));
    }
    None
}

/// Why an add-on gauge is refused, or `None` when it is well-formed. The
/// same shape as a counter except the value: a gauge is any finite number,
/// negative included (a backlog delta, a temperature), and its name must
/// NOT end in `_total` — that suffix is the counter convention, and one name
/// rendered under two `# TYPE` lines is a scrape Prometheus refuses.
pub fn addon_gauge_refusal(name: &str, labels: &HashMap<String, String>, value: f64) -> Option<String> {
    if !is_metric_word(name, 80) || name.ends_with("_total") {
        return Some(format!("gauge name {name:?} must be lowercase snake_case and not end in _total"));
    }
    if let Some(why) = addon_labels_refusal(labels) {
        return Some(why);
    }
    if !value.is_finite() {
        return Some("value must be a finite number".to_string());
    }
    None
}

fn addon_labels_refusal(labels: &HashMap<String, String>) -> Option<String> {
    if labels.len() > ADDON_MAX_LABELS {
        return Some(format!("at most {ADDON_MAX_LABELS} labels"));
    }
    for (k, v) in labels {
        if !is_metric_word(k, 32) || k == ADDON_SOURCE_LABEL || k.starts_with("__") {
            return Some(format!("label name {k:?} is not allowed"));
        }
        if v.len() > ADDON_MAX_LABEL_VALUE {
            return Some(format!("label {k:?} value is longer than {ADDON_MAX_LABEL_VALUE}"));
        }
    }
    None
}

/// How many add-on series `keys` holds for `source` — label boundary, not
/// a substring: `myaddon="evolve"` is a different label.
fn addon_series_held<'a>(keys: impl Iterator<Item = &'a String>, source: &str) -> usize {
    let mine = format!("{ADDON_SOURCE_LABEL}=\"{}\"", escape_label(source));
    let (first, later) = (format!("{{{mine}"), format!(",{mine}"));
    keys.filter(|k| k.starts_with(ADDON_COUNTER_PREFIX) && (k.contains(&first) || k.contains(&later)))
        .count()
}

impl MetricsState {
    /// Increment an add-on counter: `noo_addon_<name>{addon="<source>",…}`.
    /// Validated by the caller ([`addon_counter_refusal`]); refused here only
    /// when it would be a NEW series past the source's [`ADDON_SERIES_CAP`].
    pub async fn inc_addon_counter(
        &self,
        source: &str,
        name: &str,
        labels: &HashMap<String, String>,
        value: u64,
    ) -> Result<(), String> {
        let key = addon_key(name, labels, source);
        // Both locks, counters first, in the same order `set_addon_gauge`
        // takes them: the cap is ONE budget across the source's counters
        // and gauges, so both maps are read under both write locks.
        let mut counters = self.counters.write().await;
        if !counters.contains_key(&key) {
            let gauges = self.gauges.read().await;
            self.admit_addon_series(source, counters.keys().chain(gauges.keys()))?;
            counters.insert(key.clone(), Arc::new(AtomicU64::new(0)));
        }
        counters[&key].fetch_add(value, Ordering::Relaxed);
        Ok(())
    }

    /// Set an add-on gauge: `noo_addon_<name>{addon="<source>",…}`, rendered
    /// under `# TYPE … gauge`. Validated by the caller
    /// ([`addon_gauge_refusal`]); shares the source's [`ADDON_SERIES_CAP`]
    /// with its counters, so a gauge with an unbounded label cannot grow the
    /// scrape either. Last write wins, as a gauge does.
    pub async fn set_addon_gauge(
        &self,
        source: &str,
        name: &str,
        labels: &HashMap<String, String>,
        value: f64,
    ) -> Result<(), String> {
        let key = addon_key(name, labels, source);
        let counters = self.counters.write().await;
        let mut gauges = self.gauges.write().await;
        if !gauges.contains_key(&key) {
            self.admit_addon_series(source, counters.keys().chain(gauges.keys()))?;
            gauges.insert(key.clone(), Arc::new(AtomicU64::new(0)));
        }
        gauges[&key].store(value.to_bits(), Ordering::Relaxed);
        Ok(())
    }

    fn admit_addon_series<'a>(&self, source: &str, held_keys: impl Iterator<Item = &'a String>) -> Result<(), String> {
        let held = addon_series_held(held_keys, source);
        if held >= ADDON_SERIES_CAP {
            return Err(format!(
                "source {source:?} already holds {held} add-on series (cap {ADDON_SERIES_CAP})"
            ));
        }
        Ok(())
    }
}

fn addon_key(name: &str, labels: &HashMap<String, String>, source: &str) -> String {
    let mut all = labels.clone();
    all.insert(ADDON_SOURCE_LABEL.to_string(), source.to_string());
    format_key(&format!("{ADDON_COUNTER_PREFIX}{name}"), Some(&all))
}

pub(crate) fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

// ───────────────────────────────────────────────────────────────────
// NATS bridge — Python ML modules push counter/gauge updates here.
// The `metrics.>` NATS subscriber that used to live here is gone: it existed for "Python ML modules" to push counters, and nothing
// in this repo — Python, Rust or Go — has ever published on that subject.
// A subscription with no publisher is a standing grant nothing uses, and
// the `/metrics` output it fed is populated in-process.

// ───────────────────────────────────────────────────────────────────
// DB-backed gauge collection (run on each /metrics scrape).
// ───────────────────────────────────────────────────────────────────

/// Result of a per-scrape DB collection. None entries mean the query
/// failed; the corresponding metric is omitted (don't poison the scrape).
pub struct DbGauges {
    pub pages_embedding_backlog: Option<i64>,
    pub temporal_edges_total: Option<i64>,
    pub nats_dlq_pending: Option<i64>,
    pub nats_dlq_abandoned: Option<i64>,
    pub conversations_total: Option<i64>,
    pub entries_total: Option<i64>,
    // Security signals (last 5 min) so Prometheus/Alertmanager can alert on
    // them — previously no security series existed to alert on (H-L4).
    pub auth_failures_5m: Option<i64>,
    pub exec_denials_5m: Option<i64>,
}

pub async fn collect_db_gauges(db: &sqlx::PgPool) -> DbGauges {
    DbGauges {
        // Embeddings live in a separate `page_embeddings` table joined
        // by page_id — `pages` itself has no `embedding` column. The
        // previous query (`WHERE embedding IS NULL`) erroring every
        // 15s flooded postgres logs and made the metric a permanent 0.
        // This LEFT JOIN form matches `eval_unembedded_documents` in
        // autonomy_evaluators.rs so both surfaces agree.
        //
        // "Backlog" must count rows with NO USABLE VECTOR, which includes a
        // row whose embedding is NULL — not only a missing row. A dimension
        // migration keeps rows and blanks vectors, so the missing-row form
        // reported a backlog of 0 for a corpus that was entirely unembedded.
        // Held documents (`docs.held_at`) are excluded: kept out of
        // embedding on purpose, so not a backlog.
        pages_embedding_backlog: scalar_count(
            db,
            &crate::autonomy_evaluators::sql_unembedded_pages(crate::held_column::present(db).await),
        )
        .await,
        temporal_edges_total: scalar_count(db, "SELECT COUNT(*) FROM noo_temporal_edges").await,
        nats_dlq_pending: scalar_count(
            db,
            "SELECT COUNT(*) FROM noo_nats_dlq WHERE succeeded_at IS NULL",
        )
        .await,
        nats_dlq_abandoned: scalar_count(
            db,
            "SELECT COUNT(*) FROM noo_nats_dlq \
             WHERE succeeded_at IS NULL AND next_retry_at IS NULL",
        )
        .await,
        conversations_total: scalar_count(db, "SELECT COUNT(*) FROM noo_conversations").await,
        entries_total: scalar_count(db, "SELECT COUNT(*) FROM noo_entries").await,
        auth_failures_5m: scalar_count(
            db,
            "SELECT COUNT(*) FROM noo_security_audit \
             WHERE event_type = 'auth_failure' AND timestamp > NOW() - INTERVAL '5 minutes'",
        )
        .await,
        exec_denials_5m: scalar_count(
            db,
            "SELECT COUNT(*) FROM noo_security_audit \
             WHERE event_type = 'exec_denied' AND timestamp > NOW() - INTERVAL '5 minutes'",
        )
        .await,
    }
}

async fn scalar_count(db: &sqlx::PgPool, sql: &str) -> Option<i64> {
    // Every caller passes a literal or `sql_unembedded_pages`, which is built
    // from constants: nothing caller-supplied reaches the string.
    match sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql)).fetch_one(db).await {
        Ok(n) => Some(n),
        Err(e) => {
            tracing::debug!(sql, error = %e, "metrics_db_scalar_failed");
            None
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Filesystem-backed gauge: recall memory total bytes.
// ───────────────────────────────────────────────────────────────────

/// Recursively size a directory; None on any I/O error.
pub fn dir_size_bytes(path: &std::path::Path) -> Option<u64> {
    fn walk(p: &std::path::Path, acc: &mut u64) -> std::io::Result<()> {
        if !p.exists() {
            return Ok(());
        }
        let meta = std::fs::symlink_metadata(p)?;
        if meta.is_file() {
            *acc += meta.len();
            return Ok(());
        }
        if meta.is_dir() {
            for entry in std::fs::read_dir(p)? {
                walk(&entry?.path(), acc)?;
            }
        }
        Ok(())
    }
    let mut total = 0u64;
    walk(path, &mut total).ok().map(|_| total)
}

#[cfg(test)]
mod addon_counter_tests {
    use super::*;

    fn labels(kv: &[(&str, &str)]) -> HashMap<String, String> {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// Evolve's one counter, as its client sends it, lands prefixed and
    /// attributed — the source from the credential, not the body.
    #[tokio::test]
    async fn an_addon_counter_renders_prefixed_and_attributed() {
        let m = MetricsState::new();
        assert!(addon_counter_refusal("hofstadter_rollback_events_total", &HashMap::new(), 3.0).is_none());
        m.inc_addon_counter("evolve", "hofstadter_rollback_events_total", &HashMap::new(), 3).await.unwrap();
        m.inc_addon_counter("evolve", "hofstadter_rollback_events_total", &HashMap::new(), 2).await.unwrap();
        let out = m.render().await;
        assert!(out.contains("# TYPE noo_addon_hofstadter_rollback_events_total counter"), "{out}");
        assert!(out.contains("noo_addon_hofstadter_rollback_events_total{addon=\"evolve\"} 5"), "{out}");
    }

    #[test]
    fn the_source_is_one_name_whichever_credential_the_addon_holds() {
        assert_eq!(addon_source("addon:svc:evolve"), "evolve");
        assert_eq!(addon_source("pai-evolve"), "evolve");
        assert_eq!(addon_source("addon:svc:trellion-intel"), "trellion_intel");
        assert_eq!(addon_source("noo-trellion"), "trellion");
    }

    #[test]
    fn malformed_increments_are_refused_with_the_reason() {
        let none = HashMap::new();
        for (name, value) in [
            ("rollbacks", 1.0),                // not a _total counter
            ("Hofstadter_total", 1.0),         // not snake_case
            ("x_total", 0.0),                  // not positive
            ("x_total", 1.5),                  // not whole
            ("x_total", f64::NAN),
            ("x_total", 2_000_000.0),          // over the per-call cap
        ] {
            assert!(addon_counter_refusal(name, &none, value).is_some(), "{name} {value}");
        }
        for bad in [
            labels(&[("addon", "trellion")]), // the source label is the gateway's
            labels(&[("__name__", "x")]),
            labels(&[("Kind", "x")]),
            labels(&[("a", "1"), ("b", "1"), ("c", "1"), ("d", "1"), ("e", "1")]),
            labels(&[("kind", &"v".repeat(65))]),
        ] {
            assert!(addon_counter_refusal("x_total", &bad, 1.0).is_some(), "{bad:?}");
        }
    }

    /// An unbounded label would grow the scrape forever; past the cap the
    /// source's NEW series are refused, its existing ones keep counting, and
    /// another source is unaffected.
    #[tokio::test]
    async fn a_source_cannot_grow_the_scrape_without_limit() {
        let m = MetricsState::new();
        for i in 0..ADDON_SERIES_CAP {
            m.inc_addon_counter("evolve", "x_total", &labels(&[("id", &i.to_string())]), 1).await.unwrap();
        }
        let over = m.inc_addon_counter("evolve", "x_total", &labels(&[("id", "new")]), 1).await;
        assert!(over.is_err(), "the cap must refuse a new series");
        m.inc_addon_counter("evolve", "x_total", &labels(&[("id", "0")]), 1).await.expect("existing series keep counting");
        m.inc_addon_counter("trellion", "x_total", &HashMap::new(), 1).await.expect("another source is unaffected");
        // a label NAMED like the source does not count against it
        let m2 = MetricsState::new();
        m2.inc_addon_counter("other", "y_total", &labels(&[("myaddon", "evolve")]), 1).await.unwrap();
        for i in 0..ADDON_SERIES_CAP {
            m2.inc_addon_counter("evolve", "x_total", &labels(&[("id", &i.to_string())]), 1).await.unwrap();
        }
    }

    /// Trellion's gauges (`set_gauge` in its observability module, which
    /// published to a NATS subject nothing read) land prefixed, attributed,
    /// typed as a gauge, and last-write-wins.
    #[tokio::test]
    async fn an_addon_gauge_renders_prefixed_attributed_and_last_write_wins() {
        let m = MetricsState::new();
        assert!(addon_gauge_refusal("embedding_backlog", &HashMap::new(), 12.0).is_none());
        m.set_addon_gauge("trellion", "embedding_backlog", &HashMap::new(), 12.0).await.unwrap();
        m.set_addon_gauge("trellion", "embedding_backlog", &HashMap::new(), 7.5).await.unwrap();
        m.set_addon_gauge("trellion", "embedding_backlog", &labels(&[("model", "harrier")]), -1.0).await.unwrap();
        let out = m.render().await;
        assert!(out.contains("# TYPE noo_addon_embedding_backlog gauge"), "{out}");
        assert!(out.contains("noo_addon_embedding_backlog{addon=\"trellion\"} 7.5"), "{out}");
        assert!(out.contains("noo_addon_embedding_backlog{addon=\"trellion\",model=\"harrier\"} -1"), "{out}");
        assert!(!out.contains("noo_addon_embedding_backlog{addon=\"trellion\"} 12"), "a gauge is not a sum: {out}");
    }

    #[test]
    fn malformed_gauges_are_refused_with_the_reason() {
        let none = HashMap::new();
        for (name, value) in [
            ("backlog_total", 1.0),   // the counter suffix
            ("Backlog", 1.0),         // not snake_case
            ("", 1.0),
            ("backlog", f64::NAN),
            ("backlog", f64::INFINITY),
        ] {
            assert!(addon_gauge_refusal(name, &none, value).is_some(), "{name} {value}");
        }
        // Unlike a counter, zero, negatives and fractions are all values.
        for value in [0.0, -3.0, 0.25, 1e12] {
            assert!(addon_gauge_refusal("backlog", &none, value).is_none(), "{value}");
        }
        for bad in [
            labels(&[("addon", "trellion")]),
            labels(&[("__name__", "x")]),
            labels(&[("a", "1"), ("b", "1"), ("c", "1"), ("d", "1"), ("e", "1")]),
            labels(&[("kind", &"v".repeat(65))]),
        ] {
            assert!(addon_gauge_refusal("backlog", &bad, 1.0).is_some(), "{bad:?}");
        }
    }

    /// One budget per source across counters AND gauges: a source at the cap
    /// on counters cannot open a new gauge series, existing gauges keep
    /// updating, and another source is unaffected.
    #[tokio::test]
    async fn the_series_cap_is_shared_between_counters_and_gauges() {
        let m = MetricsState::new();
        m.set_addon_gauge("evolve", "g", &labels(&[("id", "kept")]), 1.0).await.unwrap();
        for i in 0..ADDON_SERIES_CAP - 1 {
            m.inc_addon_counter("evolve", "x_total", &labels(&[("id", &i.to_string())]), 1).await.unwrap();
        }
        assert!(m.set_addon_gauge("evolve", "g", &labels(&[("id", "new")]), 1.0).await.is_err());
        assert!(m.inc_addon_counter("evolve", "x_total", &labels(&[("id", "new")]), 1).await.is_err());
        m.set_addon_gauge("evolve", "g", &labels(&[("id", "kept")]), 2.0).await.expect("existing gauge keeps updating");
        m.set_addon_gauge("trellion", "g", &HashMap::new(), 1.0).await.expect("another source is unaffected");
    }
}
