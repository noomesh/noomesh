// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A prompt an Ollama cut, on the raw proxy (`/v1/chat/completions`,
//! `/api/external/chat/completions`), flagged after the fact (i802 step 1,
//! approved by the operator 2026-11-15: flag-only by default).
//!
//! The raw proxy stamps the decided `num_ctx` but never runs the
//! coordinator's fit check, so a caller's prompt longer than that context is
//! cut by Ollama in silence: it keeps the head and the last half, and the
//! answer is to a prompt the caller never sent. The cut is read off the
//! backend's own count with the coordinator's rule
//! ([`crate::chat_context::read_call`], the i802 D signature), and said:
//! - `X-Noo-Context-Truncated: <evaluated>/<sent_estimate>/<context>` and
//!   `usage.noo_truncated` on a non-streaming answer (a stream's headers are
//!   gone by the time its count arrives: the metric and the log carry it);
//! - [`METRIC`]`{consumer, model}` on every cut;
//! - one warn log per (consumer, model) per hour. No prompt text, ever.
//!
//! vLLM never cuts (it refuses an over-long prompt itself), so only an
//! Ollama candidate with a decided context is watched.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// Cuts seen on the raw proxy, by caller and model.
pub const METRIC: &str = "noo_context_truncated_total";
/// The response header on a non-streaming answer whose prompt was cut.
pub const HEADER: &str = "x-noo-context-truncated";
/// At most one warn line per (consumer, model) in this window.
pub const WARN_EVERY: Duration = Duration::from_secs(3600);

/// What one call is watched with: the context the Ollama runs it at, the
/// estimate of what was sent, and whose call it is.
#[derive(Clone)]
pub struct CutWatch {
    pub ctx: u64,
    pub sent_estimate: u64,
    pub backend_url: String,
    pub model: String,
    /// A service key's consumer or the path's name: never a username.
    pub consumer: String,
    pub metrics: Arc<crate::metrics::MetricsState>,
}

impl std::fmt::Debug for CutWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CutWatch")
            .field("ctx", &self.ctx)
            .field("sent_estimate", &self.sent_estimate)
            .field("model", &self.model)
            .field("consumer", &self.consumer)
            .finish_non_exhaustive()
    }
}

/// A cut, with the three numbers the header and the usage field carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cut {
    pub evaluated: u64,
    pub sent_estimate: u64,
    pub context: u64,
}

impl Cut {
    pub fn header_value(&self) -> String {
        format!("{}/{}/{}", self.evaluated, self.sent_estimate, self.context)
    }

    pub fn usage_field(&self) -> Value {
        json!({"evaluated": self.evaluated, "sent_estimate": self.sent_estimate, "context": self.context})
    }
}

impl CutWatch {
    /// Was this call cut, by the backend's own `evaluated` count?
    pub fn judge(&self, evaluated: u64) -> Option<Cut> {
        let calib = crate::chat_context::calibration(&self.backend_url, &self.model);
        judge_with(self.ctx, self.sent_estimate, evaluated, calib)
    }

    /// Count the cut, and say it once an hour per (consumer, model). The
    /// (backend URL, model) ratio goes back to untrusted: a cut means the
    /// prompt was larger than the ratio in use said.
    pub async fn note(&self, cut: &Cut) {
        crate::chat_context::forget(&self.backend_url, &self.model);
        let labels = HashMap::from([
            ("consumer".to_string(), self.consumer.clone()),
            ("model".to_string(), self.model.clone()),
        ]);
        self.metrics.inc_counter(METRIC, Some(&labels), 1).await;
        if warn_due(&self.consumer, &self.model, Instant::now()) {
            tracing::warn!(
                consumer = %self.consumer, model = %self.model,
                evaluated = cut.evaluated, sent_estimate = cut.sent_estimate, context = cut.context,
                "raw_chat_context_truncated"
            );
        }
    }
}

/// The rule, pure: the coordinator's cut signature on the backend's count.
pub fn judge_with(ctx: u64, sent_estimate: u64, evaluated: u64, calib: crate::chat_context::Calibration) -> Option<Cut> {
    (crate::chat_context::read_call(ctx, sent_estimate, evaluated, calib) == crate::chat_context::CallRead::Cut)
        .then_some(Cut { evaluated, sent_estimate, context: ctx })
}

/// Refuse mode (a key set to `refuse`): would this prompt overflow an
/// Ollama run at `ctx`? The coordinator's rule for a turn's instructions
/// ([`crate::chat_context::instructions_overflow`] on
/// [`crate::chat_context::max_input_for`]): the trusted ratio, else the
/// kindest measured, so an uncalibrated box refuses only a prompt that is
/// over on any reading. A prompt this lets through and the Ollama still
/// cuts is flagged as in flag mode.
pub fn overflows(sent_estimate: u64, ctx: u64, calib: crate::chat_context::Calibration) -> bool {
    crate::chat_context::instructions_overflow(sent_estimate, crate::chat_context::max_input_for(ctx), calib)
}

/// The refusal's line to the caller: the model and its context, never the
/// node or an address.
pub fn refusal_line(model: &str, ctx: u64) -> String {
    format!(
        "this prompt is longer than the {ctx}-token context of {model}, and this key is set to refuse \
         rather than cut it: send a shorter prompt, or ask the operator for a model with a larger context"
    )
}

type Warned = HashMap<(String, String), Instant>;
static WARNED: std::sync::LazyLock<Mutex<Warned>> = std::sync::LazyLock::new(Default::default);

/// Whether a warn line is due for (consumer, model) at `now`, recording it.
fn warn_due(consumer: &str, model: &str, now: Instant) -> bool {
    let mut seen = WARNED.lock().unwrap_or_else(|e| e.into_inner());
    warn_due_in(&mut seen, consumer, model, now)
}

fn warn_due_in(seen: &mut Warned, consumer: &str, model: &str, now: Instant) -> bool {
    let key = (consumer.to_string(), model.to_string());
    match seen.get(&key) {
        Some(at) if now.saturating_duration_since(*at) < WARN_EVERY => false,
        _ => {
            seen.insert(key, now);
            true
        }
    }
}

/// Put the cut on a non-streaming OpenAI body: `usage.noo_truncated`.
pub fn mark_body(data: &mut Value, cut: &Cut) {
    if let Some(obj) = data.as_object_mut() {
        let usage = obj.entry("usage").or_insert_with(|| json!({}));
        if let Some(u) = usage.as_object_mut() {
            u.insert("noo_truncated".into(), cut.usage_field());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_context::Calibration;

    fn fresh() -> Calibration {
        Calibration::default()
    }

    /// A 4096 Ollama cut a ~9,000-token prompt: it read 2,053 (its
    /// `ctx/2 + 5`). The header says evaluated/sent/context.
    #[test]
    fn a_cut_is_read_off_the_backends_count() {
        let cut = judge_with(4096, 9000, crate::chat_context::cut_length(4096), fresh()).expect("cut");
        assert_eq!(cut, Cut { evaluated: crate::chat_context::cut_length(4096), sent_estimate: 9000, context: 4096 });
        assert_eq!(cut.header_value(), format!("{}/9000/4096", crate::chat_context::cut_length(4096)));
        // Read whole: a small prompt, or a count far from the cut length.
        assert_eq!(judge_with(4096, 900, 380, fresh()), None);
        assert_eq!(judge_with(32768, 5640, 3956, fresh()), None, "the fleet's largest week-one prompt: whole");
        // On the line but small enough to be whole: not a cut.
        assert_eq!(judge_with(4096, 2100, crate::chat_context::cut_length(4096), fresh()), None);
    }

    #[test]
    fn the_cut_goes_on_the_body_beside_the_backends_usage() {
        let mut data = json!({"choices": [], "usage": {"prompt_tokens": 2053, "completion_tokens": 9}});
        mark_body(&mut data, &Cut { evaluated: 2053, sent_estimate: 9000, context: 4096 });
        assert_eq!(data["usage"]["prompt_tokens"], 2053, "the backend's own count is kept");
        assert_eq!(data["usage"]["noo_truncated"], json!({"evaluated": 2053, "sent_estimate": 9000, "context": 4096}));
        let mut bare = json!({"choices": []});
        mark_body(&mut bare, &Cut { evaluated: 1, sent_estimate: 2, context: 3 });
        assert_eq!(bare["usage"]["noo_truncated"]["context"], 3);
    }

    /// The wiring, held by source: the raw proxy watches each Ollama attempt
    /// it stamped, judges a whole answer's count before returning it (field,
    /// header, note), and hands the watch to the stream tap, which judges
    /// the stream's last count when it ends.
    #[test]
    fn the_raw_proxy_and_the_stream_tap_judge_the_count() {
        let raw = crate::test_src::own_code(include_str!("routes/raw_chat.rs"));
        let send = crate::test_src::fn_body(&raw, "pub async fn send_with_failover_pinned<F>(");
        assert!(send.contains("sent_in.lock()") && send.contains("coordinator::estimate_tokens(msgs)"), "each stamped attempt is recorded");
        let json_arm = &send[send.find("CoreBody::Json(mut data) =>").expect("the whole-answer arm")..];
        let judged = json_arm.find("w.judge(p as u64)").expect("judged");
        for step in ["crate::context_cut::mark_body(&mut data, &cut);", "served.truncated = Some(cut.header_value());", "w.note(&cut).await;"] {
            assert!(json_arm[judged..].contains(step), "{step}");
        }
        assert!(send.contains("cut: watch.clone().map(Box::new),"), "the stream tap gets the watch");
        let usage = crate::test_src::own_code(include_str!("usage.rs"));
        let drop = crate::test_src::fn_body(&usage, "impl Drop for UsageTap \u{7b}");
        assert!(drop.contains("w.judge(u64::from(p))") && drop.contains("w.note(&cut).await"), "{drop}");
    }

    /// Refuse mode's wiring, held by source: a key's name (never a path
    /// label) is looked up; before anything is sent, an Ollama the prompt
    /// overflows is dropped, and with none left the call is a 413
    /// `context_too_small` carrying the line.
    #[test]
    fn a_refusing_key_is_judged_before_anything_is_sent() {
        let raw = crate::test_src::own_code(include_str!("routes/raw_chat.rs"));
        let send = crate::test_src::fn_body(&raw, "pub async fn send_with_failover_pinned<F>(");
        let filter = send.find("if refuses_overflow(state, &actor).await").expect("the mode is read");
        let fit = send.find("base = fitting(state, candidates, &mut build).await?;").expect("the filter runs");
        let sent = send.find("failover_core(").expect("the send");
        assert!(filter < fit && fit < sent, "judged before the send");
        let mode = crate::test_src::fn_body(&raw, "async fn refuses_overflow(");
        assert!(mode.contains("(true, Some(name))") && mode.contains("ContextOverflow::Refuse"), "{mode}");
        let fitting = crate::test_src::fn_body(&raw, "async fn fitting<F>(");
        for step in [
            "crate::context_cut::overflows(est, ctx, crate::chat_context::calibration(&c.url, &c.model))",
            "StatusCode::PAYLOAD_TOO_LARGE",
            "\"context_too_small\"",
            "crate::context_cut::refusal_line(&c.model, ctx)",
        ] {
            assert!(fitting.contains(step), "{step}");
        }
        let inference = crate::test_src::own_code(include_str!("routes/inference.rs"));
        let bind = crate::test_src::fn_body(&inference, "pub(crate) fn bind_identity(");
        assert_eq!(bind.matches("keyed: true").count(), 2, "a bound and an unbound key are both keyed");
    }

    /// Refuse mode judges with the coordinator's rule: over on the kindest
    /// ratio while uncalibrated, on the trusted ratio once calibrated.
    #[test]
    fn refuse_mode_refuses_only_a_prompt_that_is_over_on_the_rule() {
        let max = crate::chat_context::max_input_for(4096);
        let kind = crate::chat_context::REFUSE_UNTRUSTED_RATIO;
        let at = |r: f64| (max as f64 / r).floor() as u64;
        assert!(!overflows(at(kind), 4096, fresh()), "on the line: sent");
        assert!(overflows(at(kind) + 100, 4096, fresh()), "over on the kindest ratio: refused");
        let trusted = Calibration { ratio: 0.64, samples: 3 };
        assert!(overflows(at(0.64) + 100, 4096, trusted));
        assert!(!overflows(at(0.64) - 100, 4096, trusted));
        assert!(!overflows(5640, 32768, fresh()), "the fleet's largest week-one prompt fits 32k");
        let line = refusal_line("gemma4:e4b", 4096);
        assert!(line.contains("4096-token context of gemma4:e4b") && line.contains("refuse"), "{line}");
    }

    /// One warn per (consumer, model) per hour; another caller or model is
    /// its own line.
    #[test]
    fn the_warn_is_hourly_per_caller_and_model() {
        let mut seen = Warned::new();
        let t0 = Instant::now();
        assert!(warn_due_in(&mut seen, "paiserve", "gemma4:e4b", t0));
        assert!(!warn_due_in(&mut seen, "paiserve", "gemma4:e4b", t0 + Duration::from_secs(60)));
        assert!(warn_due_in(&mut seen, "pai-trading", "gemma4:e4b", t0 + Duration::from_secs(60)));
        assert!(warn_due_in(&mut seen, "paiserve", "gemma4:12b", t0 + Duration::from_secs(60)));
        assert!(warn_due_in(&mut seen, "paiserve", "gemma4:e4b", t0 + WARN_EVERY));
    }
}
