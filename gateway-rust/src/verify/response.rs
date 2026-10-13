// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Response-level verifiers: things that run AFTER the coordinator's
//! agentic loop produces a final response, before that response is
//! shown to the user / persisted / shipped to a channel.
//!
//! All functions here are pure — no DB, no HTTP, no async. They take
//! a string (and sometimes a tool-call log) and either inspect or
//! mutate it. Easy to unit-test, easy to compose.

use serde_json::Value;

// ─── strip_think_blocks ──────────────────────────────────────────────

/// Strip `<think>...</think>` blocks from assistant response before
/// persisting or displaying. Thinking is ephemeral reasoning, not part
/// of the answer.
///
/// Handles both well-formed (`<think>X</think>`) and unclosed
/// (`<think>X<EOF>`) cases. Returns trimmed.
pub fn strip_think_blocks(text: &str) -> String {
    // Only the bare marker here: this runs on every chat reply, where a
    // gemma answer with no heading is still the answer. The deliverable rule
    // (`strip_gemma_thought`) is for reports — see `classify_response_quality`.
    let text = drop_thought_markers(text);
    let mut result = String::new();
    let mut remaining = text.as_str();

    while let Some(start) = remaining.find("<think>") {
        result.push_str(&remaining[..start]);
        if let Some(end) = remaining[start..].find("</think>") {
            remaining = &remaining[start + end + 8..]; // 8 = len("</think>")
        } else {
            // Unclosed think block — drop everything after <think>
            return result.trim().to_string();
        }
    }
    result.push_str(remaining);
    result.trim().to_string()
}

/// Remove gemma-4's untagged reasoning from a NON-streamed reply.
///
/// gemma-4 opens a reasoning channel with `<|channel>thought` and closes it
/// with `<channel|>`; vLLM strips both special tokens and has no gemma
/// reasoning parser, so the reply arrives as plain text: a bare `thought`
/// line, the reasoning, then the answer with no boundary. The streaming path
/// already treats a leading `thought` as a virtual `<think>`; everything else
/// kept it — reports were saved and judged with the model's planning as their
/// body, and passed as "success" (weekly_research, 2026-09-20/28).
///
/// Rules, in order:
/// - every bare `thought` line is a channel marker, never content — dropped;
/// - a reply that OPENED with one is reasoning up to its first markdown
///   heading, where the deliverable begins; with no heading after it, the
///   whole reply was reasoning and nothing visible remains.
///
/// For a DELIVERABLE (a report, a log entry) — not for chat, where an answer
/// needs no heading. Chat gets only [`drop_thought_markers`].
pub fn strip_gemma_thought(text: &str) -> String {
    let opened = text.lines().find(|l| !l.trim().is_empty()).is_some_and(is_thought_marker);
    let kept: Vec<&str> = text.lines().filter(|l| !is_thought_marker(l)).collect();
    if !opened {
        return kept.join("\n");
    }
    match kept.iter().position(|l| l.trim_start().starts_with('#')) {
        Some(i) => kept[i..].join("\n"),
        None => String::new(),
    }
}

/// Drop gemma's bare `thought` channel-marker lines and nothing else.
pub fn drop_thought_markers(text: &str) -> String {
    if !text.lines().any(is_thought_marker) {
        return text.to_string();
    }
    text.lines().filter(|l| !is_thought_marker(l)).collect::<Vec<_>>().join("\n")
}

fn is_thought_marker(line: &str) -> bool {
    line.trim().eq_ignore_ascii_case("thought")
}

// ─── looks_like_malformed_tool_call ──────────────────────────────────

/// Returns true when the trimmed visible content contains
/// `<execute_tool>` and the wrapped body takes up most of the content,
/// indicating the model is trying to *call* a tool via the wrong syntax
/// (not just *describe* one in prose).
///
/// Failure mode this catches: some local models (e.g. gemma-4) emit
/// `<execute_tool>name{args}</execute_tool>` as text instead of via the
/// structured `tool_calls` field. Without this check, that XML becomes
/// the user-visible final answer (or a Drive doc body).
///
/// Threshold: wrapped body must be >50% of the visible content. This
/// rejects responses dominated by the malformed call while allowing
/// legitimate prose that happens to mention `<execute_tool>` (e.g. an
/// agent explaining what NOT to do).
pub fn looks_like_malformed_tool_call(visible: &str) -> bool {
    let trimmed = visible.trim();
    if !trimmed.contains("<execute_tool>") {
        return false;
    }
    let start = match trimmed.find("<execute_tool>") {
        Some(i) => i,
        None => return false,
    };
    let after = &trimmed[start + "<execute_tool>".len()..];
    let end_rel = match after.find("</execute_tool>") {
        Some(i) => i,
        None => return false,
    };
    let inner_len = end_rel;
    inner_len * 2 > trimmed.chars().count()
}

// ─── verify_no_scheduling_hallucination ──────────────────────────────

/// Pure detector: did the model claim to have scheduled a task while
/// failing to actually call any scheduling tool this turn?
///
/// Two parts:
/// 1. None of `noo_schedule_task` / `noo_heartbeat_create_task` appear
///    in this turn's tool_calls.
/// 2. The response text contains "task" AND one of a tight set of
///    creation-claim phrases ("successfully queued", "has been
///    scheduled", "i've created the…", etc.).
///
/// Conservative on purpose. False positives nudge a healthy turn into
/// an unnecessary extra iteration; we'd rather miss a subtle
/// hallucination than corrupt a working session.
pub fn detect_scheduling_hallucination(response: &str, tool_calls: &[Value]) -> bool {
    const SCHEDULING_TOOLS: &[&str] = &[
        "noo_schedule_task",
        "noo_heartbeat_create_task",
    ];

    let scheduling_tool_ran = tool_calls.iter().any(|tc| {
        let name = tc.get("name").and_then(|v| v.as_str())
            .or_else(|| tc.get("function").and_then(|f| f.get("name")).and_then(|v| v.as_str()))
            .unwrap_or("");
        SCHEDULING_TOOLS.contains(&name)
    });
    if scheduling_tool_ran {
        return false;
    }

    let response_lower = response.to_lowercase();
    if !response_lower.contains("task") {
        return false;
    }

    const CLAIM_PHRASES: &[&str] = &[
        "successfully queued",
        "successfully scheduled",
        "successfully created",
        "successfully configured",
        "successfully set up",
        "has been queued",
        "has been scheduled",
        "has been created",
        "has been configured",
        "has been set up",
        "i've created the",
        "i've scheduled the",
        "i've queued the",
        "i've set up the",
        "i've configured the",
        "i have created the",
        "i have scheduled the",
        "i have queued the",
        "task is now scheduled",
        "task is now queued",
        "task is now active",
    ];
    CLAIM_PHRASES.iter().any(|p| response_lower.contains(p))
}

/// Ralph-loop nudge for the scheduling-hallucination case. Pushed as
/// `role=user` mid-loop so the model retries with a corrected plan
/// (call the tool for real) instead of returning a false-claim
/// response to the user.
///
/// Returned as a stable `&'static str` so the loop's nudge-history
/// tracking can compare-by-pointer-equivalence to detect "we just
/// pushed this same nudge 3 times in a row, give up."
pub fn scheduling_hallucination_nudge() -> &'static str {
    "Your previous message claimed to schedule a task, but `noo_schedule_task` is not in your \
     tool_calls for this turn. Either call `noo_schedule_task` now with explicit name / do / when \
     arguments and report the verified result, or correct your previous statement (the task has \
     NOT been created)."
}

/// Catch the "I successfully scheduled a task" hallucination after
/// the agentic loop has finished — final fallback for when the
/// mid-loop nudge didn't recover. Prepends a correction warning to
/// the response so the user isn't misled.
///
/// Use the pair `detect_scheduling_hallucination` +
/// `scheduling_hallucination_nudge` inside the loop; this function is
/// the last-resort post-loop fixer.
pub fn verify_no_scheduling_hallucination(response: &mut String, tool_calls: &[Value]) {
    if !detect_scheduling_hallucination(response, tool_calls) {
        return;
    }

    tracing::warn!(
        tool_calls = tool_calls.len(),
        "coordinator_scheduling_hallucination_post_loop_warning"
    );

    let warning = "⚠️ **Correction**: I said I scheduled a task, but the scheduling \
                   tool (`noo_schedule_task`) was not actually invoked this turn. \
                   The task has **not** been created. Please ask again, or check the \
                   dashboard `/tasks` panel to confirm what's actually scheduled. \
                   If this keeps happening it's a tool-call format issue on my end.\n\n---\n\n";
    *response = format!("{warning}{response}");
}


// ─── validation-error detector ──────────────────────────────────────

/// Count this turn's tool calls whose result text contains a Pydantic /
/// schema validation error. These are the "your tool call was missing
/// a required field" failures the model often misinterprets as "the
/// tool returned nothing useful."
///
/// Each entry in `tool_calls` is the json the coordinator records:
/// `{name, arguments, result: {success, output, error}}`. We check
/// both `result.output` (the formatted error message that goes back to
/// the model) and `result.error` (set when the tool wrapper raised).
pub fn count_validation_errors(tool_calls: &[Value]) -> usize {
    const VALIDATION_MARKERS: &[&str] = &[
        "validation error",
        "Field required",
        "[type=missing",
        "type=missing,",
        "PaiInference\nprompt",  // observed real failure mode
    ];
    tool_calls
        .iter()
        .filter(|tc| {
            let result = match tc.get("result") {
                Some(r) => r,
                None => return false,
            };
            // Skip explicitly successful tool calls.
            if result.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                return false;
            }
            let output = result.get("output").and_then(|v| v.as_str()).unwrap_or("");
            let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("");
            VALIDATION_MARKERS
                .iter()
                .any(|m| output.contains(m) || error.contains(m))
        })
        .count()
}

/// Ralph-loop nudge for the validation-error case. The model has
/// emitted tool calls with missing/empty required fields and is
/// likely about to give up and report "tools returned nothing."
pub fn validation_errors_nudge() -> &'static str {
    "One or more of your recent tool calls failed VALIDATION (e.g. \
     `Field required [type=missing]`). That is NOT a tool failure — the \
     tool is telling you that you didn't fill in a required argument. \
     Re-read each tool's schema in your system prompt; when you call it, \
     supply every required field with a non-empty value. Do not conclude \
     the tool is broken from a validation error."
}

// ─── tool-error-vs-success-claim detector ───────────────────────────

/// Detect the case where a tool call FAILED (success=false or non-empty
/// error) but the model's response claims success ("triggered
/// successfully", "has been done", etc.). Different from
/// `detect_scheduling_hallucination`, which catches "model claimed
/// scheduling but never called the tool" — this one catches "model
/// called the tool, got an error, and lied about it."
///
/// Conservative: only fires when at least one tool failed AND the
/// response contains an explicit success-claim phrase. Won't fire on
/// truthful failure reports ("the tool returned an error: X").
pub fn detect_tool_error_hidden_by_success_claim(
    response: &str,
    tool_calls: &[Value],
) -> bool {
    let failed = tool_calls.iter().any(|tc| {
        let result = match tc.get("result") {
            Some(r) => r,
            None => return false,
        };
        let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(true);
        let has_error = result
            .get("error")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        !success || has_error
    });
    if !failed {
        return false;
    }

    let response_lower = response.to_lowercase();
    // Truthful failure reports usually mention the error explicitly.
    // If the model is being honest, it'll say "error" / "failed" /
    // "couldn't" / "unable" near the result. Skip those.
    let honest_about_failure = response_lower.contains("error")
        || response_lower.contains("failed")
        || response_lower.contains("couldn't")
        || response_lower.contains("could not")
        || response_lower.contains("unable")
        || response_lower.contains("timed out")
        || response_lower.contains("did not")
        || response_lower.contains("didn't");
    if honest_about_failure {
        return false;
    }

    const SUCCESS_CLAIMS: &[&str] = &[
        "triggered successfully",
        "executed successfully",
        "completed successfully",
        "ran successfully",
        "has been triggered",
        "has been executed",
        "has been completed",
        "has been done",
        "done successfully",
        "successfully ran",
    ];
    SUCCESS_CLAIMS.iter().any(|p| response_lower.contains(p))
}

pub fn tool_error_hidden_nudge() -> &'static str {
    "One of your tool calls FAILED (returned an error or success=false), \
     but your response claims success. That's a hallucination. Re-read \
     the tool results above — if a call errored, tell the user it errored \
     and explain what went wrong. Do NOT claim 'triggered successfully' \
     when the tool returned an error."
}

// ─── classify_response_quality ───────────────────────────────────────

/// Outcome of a quality check on a response that's about to be saved
/// to Drive, dispatched as a heartbeat artifact, or otherwise treated
/// as a deliverable. Wraps the strip/malformed/length/stall checks so
/// call sites don't have to chain them inline (the same pattern was
/// duplicated in heartbeat_actions and routes/communication).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseQuality {
    /// Passed all checks; safe to publish.
    Usable,
    /// All text was inside `<think>...</think>` blocks; no visible content.
    Empty,
    /// `<execute_tool>` XML dominates the visible content — model tried
    /// to call a tool via the wrong syntax.
    Malformed,
    /// Visible content shorter than the per-call-site threshold (stub
    /// reply, bail-out like "should I proceed?", etc.). Carries the
    /// actual char count and the threshold for the log line.
    TooShort { chars: usize, min: usize },
    /// Visible content is progress-narration without a deliverable:
    /// "I have gathered the information and will now synthesize..."
    /// 500-2000 chars of meta-talk but no actual report content.
    /// Caught observation 2026-06-08 — model burned 2 minutes producing
    /// 530 chars of "I will now compile the report" and stopped.
    StallNarration,
    /// Visible content is one short fragment repeated over and over —
    /// a decoding loop, not a document. Length alone cannot catch this:
    /// on 2026-09-28 gemma-4 answered the weekly research prompt with the
    /// word `thought` on 1041 consecutive lines (8.3k chars), which
    /// cleared the 2500-char research floor, was written to disk as the
    /// report, and was announced to the operator as "Full report attached".
    /// Carries the distinct-line count and the total for the log line.
    Degenerate { distinct: usize, total: usize },
}

impl ResponseQuality {
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Usable)
    }

    /// One-line human reason. Stable across versions — these strings
    /// land in audit logs and user-visible "task ran but produced X"
    /// messages, so don't reword without grepping callers.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Usable => "usable",
            Self::Empty => "model produced no user-visible content (all wrapped in <think> tags)",
            Self::Malformed => "model emitted <execute_tool> XML as text instead of calling the tool",
            Self::TooShort { .. } => "model produced a stub response, not a real report",
            Self::StallNarration => "model produced progress-narration (\"I have gathered…\" / \"I will now synthesize…\") instead of the actual deliverable",
            Self::Degenerate { .. } => "model produced degenerate repeated output (one fragment looped), not a real report",
        }
    }
}

/// Classify a response as Usable / Empty / Malformed / TooShort / StallNarration.
///
/// Checks run in the order they're listed in the enum docstring above
/// — first failing check wins. Length is measured on the *trimmed
/// visible* content (after stripping `<think>`), not the raw input;
/// this catches the latent bug where a response that's 5KB of
/// `<think>` content + 30 chars of visible text would otherwise pass a
/// raw-length gate.
///
/// `min_chars` is per call site:
///   - heartbeat artifacts: 100 (any real report easily clears)
///   - chat-report Drive uploads: 800 (filter bail-outs / "let me try
///     again" responses)
///   - research_report / research_and_send: 1500 via `min_chars_for_action`
///     (real reports are 5000+ chars; 1500 is conservative)
///
/// StallNarration is checked AFTER TooShort — a 530-char response that's
/// pure stall-narration ("I have gathered...") fails the length check first.
/// But for longer (1500+ char) "I will now synthesize..." essays-about-
/// writing-the-report, this catches what length alone misses.
pub fn classify_response_quality(text: &str, min_chars: usize) -> ResponseQuality {
    // A decoding loop is named as one even when its repeated line is a
    // marker that stripping would erase — "degenerate" tells the operator
    // what happened; "empty" would not.
    if let Some((distinct, total)) = degenerate_repetition(text.trim()) {
        return ResponseQuality::Degenerate { distinct, total };
    }
    // Judged as a deliverable: gemma's leading reasoning is not the report.
    let visible = strip_think_blocks(&strip_gemma_thought(text));
    let trimmed = visible.trim();
    if trimmed.is_empty() {
        return ResponseQuality::Empty;
    }
    if looks_like_malformed_tool_call(trimmed) {
        return ResponseQuality::Malformed;
    }
    let chars = trimmed.chars().count();
    if chars < min_chars {
        return ResponseQuality::TooShort { chars, min: min_chars };
    }
    if is_progress_narration_stall(trimmed) {
        return ResponseQuality::StallNarration;
    }
    if let Some((distinct, total)) = degenerate_repetition(trimmed) {
        return ResponseQuality::Degenerate { distinct, total };
    }
    ResponseQuality::Usable
}

/// Detect a decoding loop: the same few lines repeated until the token
/// budget ran out. Returns `(distinct_lines, total_lines)` when the text
/// is long enough to judge (≥ `DEGENERATE_MIN_LINES` non-blank lines) and
/// fewer than one line in `DEGENERATE_MAX_DISTINCT_DIVISOR` is unique.
///
/// A real report never trips this: even a bullet-heavy one has almost
/// every line distinct. A short answer never trips it either — with
/// fewer than 20 lines there is nothing to call a loop. Blank lines are
/// ignored so a fragment padded with `\n\n` counts the same as one that
/// is not.
fn degenerate_repetition(text: &str) -> Option<(usize, usize)> {
    const DEGENERATE_MIN_LINES: usize = 20;
    const DEGENERATE_MAX_DISTINCT_DIVISOR: usize = 5;
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let total = lines.len();
    if total < DEGENERATE_MIN_LINES {
        return None;
    }
    let distinct = lines.iter().collect::<std::collections::HashSet<_>>().len();
    if distinct * DEGENERATE_MAX_DISTINCT_DIVISOR < total {
        Some((distinct, total))
    } else {
        None
    }
}

/// Returns the artifact-quality `min_chars` floor appropriate for an
/// action. Research actions need a much higher floor than generic
/// notifications because real reports are multi-thousand-char.
///
/// Defaults: heartbeat 100, chat-report 800 (callers can still pass an
/// explicit value to override).
pub fn min_chars_for_action(action: &str) -> usize {
    match action {
        // Research actions: real deep reports are 5000+ chars; 1500 is
        // the floor below which we know we got a stub or stall.
        "research_report" | "research_and_send" => 1500,
        // Daily briefings and similar curated narratives: 600 chars
        // covers a meaningful multi-paragraph summary.
        "daily_briefing" | "news_scan" | "chat_digest" | "conversation_summarize" => 600,
        // Generic heartbeat artifacts (cluster_health, cost_report,
        // security_audit, etc.): 100 chars is enough for the short
        // structured outputs they produce.
        _ => 100,
    }
}

/// Depth-aware "clearly too short" floor for research actions. The flat
/// 1500-char floor (~250 words) is fine for a `brief`, but a `deep` report
/// targets 15-25k chars — one that comes back at 1600 chars is a stub
/// relative to what was asked, yet would pass the flat floor and get
/// delivered. Scale the floor by configured depth so short deep/exhaustive
/// reports are rejected (→ recorded as error, retried) instead of shipped.
/// Non-research actions fall through to the flat floor.
pub fn min_chars_for_action_depth(action: &str, depth: Option<&str>) -> usize {
    if !matches!(action, "research_report" | "research_and_send") {
        return min_chars_for_action(action);
    }
    match depth.unwrap_or("standard").to_lowercase().as_str() {
        "brief" => 1500,
        "deep" => 4000,
        "exhaustive" => 6000,
        _ => 2500, // standard / unknown
    }
}

/// Detect responses that are progress-narration rather than the
/// deliverable. The model says things like "I have gathered all the
/// information and will now synthesize..." but never actually produces
/// the report.
///
/// Heuristic: count the narration phrases. If 2+ are present AND the
/// response lacks the structural markers of a real report (headers,
/// bullet lists, etc.), it's a stall.
fn is_progress_narration_stall(text: &str) -> bool {
    const NARRATION_PHRASES: &[&str] = &[
        "i have gathered",
        "i will now",
        "i'll now",
        "let me now",
        "i am compiling",
        "i'm compiling",
        "i am synthesizing",
        "i'm synthesizing",
        "i am preparing",
        "i'm preparing",
        "i will compile",
        "i will synthesize",
        "i will prepare",
        "i have collected",
        "now i will",
        "the next step",
        "i will provide",
        "i'll provide the",
        "the synthesis process",
        "the report will cover",
        "is being compiled",
        "being compiled",
        "is being prepared",
        "being prepared",
        "i am currently",
        "i'm currently",
        "currently compiling",
        "report is being",
        "due to the specific requirement",
    ];
    let lower = text.to_lowercase();
    let narration_hits = NARRATION_PHRASES
        .iter()
        .filter(|p| lower.contains(*p))
        .count();
    if narration_hits < 2 {
        return false;
    }

    // Real reports have structural markers. If the response has 2+
    // markdown headers OR 4+ bullet points, it's probably not a stall
    // even if it also includes narration phrases (some real reports
    // include "I will now examine X" preamble before the actual content).
    let header_count = text.lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with("# ") || t.starts_with("## ") || t.starts_with("### ")
    }).count();
    let bullet_count = text.lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with("- ") || t.starts_with("* ") || t.starts_with("+ ")
    }).count();
    if header_count >= 2 || bullet_count >= 4 {
        return false;
    }

    true
}


// ─── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[test]
    fn gemma_thought_is_reasoning_up_to_the_first_heading() {
        use super::{classify_response_quality, strip_gemma_thought};
        // The 2026-09-20 shape: planning, then the report.
        let r = "thought\nThe user wants a report.\nI need to search.\n# AI\n\n## Summary\nBody.";
        assert_eq!(strip_gemma_thought(r), "# AI\n\n## Summary\nBody.");
        // Reasoning only — nothing is a deliverable.
        assert_eq!(strip_gemma_thought("thought\nPlan:\n1. search\n2. write"), "");
        // Stray markers between segments go; a reply that did not open with
        // one keeps everything else.
        assert_eq!(strip_gemma_thought("## Notes\n- a\nthought\n## Outline\n1. x"), "## Notes\n- a\n## Outline\n1. x");
        assert_eq!(strip_gemma_thought("A plain answer.\nIt had a thought."), "A plain answer.\nIt had a thought.");
        // The judged text is what remains: ~3k chars of planning, every line
        // distinct (so no loop check catches it), is not a report.
        let planning = format!("thought\n{}", (1..90).map(|i| format!("Step {i}: search one more angle, then plan.\n")).collect::<String>());
        assert!(planning.chars().count() > 2500);
        assert!(!classify_response_quality(&planning, 2500).is_usable());
        // Chat: only the marker goes — an answer with no heading survives.
        assert_eq!(super::strip_think_blocks("thought\nThe answer is 42."), "The answer is 42.");
        // 1,041 bare markers (2026-09-28, saved as success) judge as empty.
        let loop_ = "thought\n".repeat(1041);
        assert!(!classify_response_quality(&loop_, 2500).is_usable());
    }

    use super::*;
    use serde_json::json;

    #[test]
    fn degenerate_thought_loop_is_rejected_despite_length() {
        // The 2026-09-28 weekly_research artifact: `thought` x 1041 lines,
        // 8.3k chars — longer than any research floor.
        let text = "thought\n".repeat(1041);
        assert!(text.chars().count() > 2500);
        let q = classify_response_quality(&text, 2500);
        assert!(
            matches!(q, ResponseQuality::Degenerate { distinct: 1, total: 1041 }),
            "got {q:?}"
        );
        assert!(!q.is_usable());
        assert!(q.reason().contains("degenerate"));
    }

    #[test]
    fn degenerate_two_line_loop_with_blank_padding_is_rejected() {
        let text = "## Summary\n\nThe report follows.\n\n".repeat(40);
        let q = classify_response_quality(&text, 100);
        assert!(matches!(q, ResponseQuality::Degenerate { distinct: 2, total: 80 }), "got {q:?}");
    }

    #[test]
    fn short_repetition_is_not_judged_degenerate() {
        // 19 non-blank lines is below the floor: too little to call a loop.
        let text = "same line\n".repeat(19);
        let q = classify_response_quality(&text, 10);
        assert!(q.is_usable(), "got {q:?}");
    }

    #[test]
    fn real_report_with_repeated_bullets_is_usable() {
        // A bullet-heavy report reuses a few lines (section separators,
        // "Source:" labels) but most lines are distinct.
        let mut text = String::from("# Weekly Research Report\n\n");
        for i in 0..30 {
            text.push_str(&format!("## Finding {i}\n\nParagraph about finding number {i} with detail.\n\n---\n\nSource:\n\n"));
        }
        let q = classify_response_quality(&text, 100);
        assert!(q.is_usable(), "got {q:?}");
    }

    #[test]
    fn strip_think_well_formed() {
        let out = strip_think_blocks("hello <think>reasoning</think> world");
        assert_eq!(out, "hello  world");
    }

    #[test]
    fn strip_think_unclosed_drops_tail() {
        let out = strip_think_blocks("visible <think>never ends");
        assert_eq!(out, "visible");
    }

    #[test]
    fn malformed_tool_call_dominant_body() {
        assert!(looks_like_malformed_tool_call(
            "<execute_tool>noo_inference{prompt: \"x\", max_tokens: 4096, ...lots of stuff...}</execute_tool>"
        ));
    }

    #[test]
    fn malformed_tool_call_just_mentioned() {
        // Long prose that just MENTIONS the syntax — not the whole content
        let s = "Here is some context. Lots of text. More text. Even more text. \
                 In rare cases, the model might emit <execute_tool>x</execute_tool> \
                 but you should not. Continue with more long text. And more text.";
        assert!(!looks_like_malformed_tool_call(s));
    }

    #[test]
    fn scheduling_no_hallucination_when_tool_ran() {
        let mut r = String::from("I have created the task as you requested.");
        verify_no_scheduling_hallucination(
            &mut r,
            &[json!({"name": "noo_schedule_task"})],
        );
        // unchanged
        assert!(!r.contains("Correction"));
    }

    #[test]
    fn scheduling_hallucination_prepends_warning() {
        let mut r = String::from("I've created the task — it will run daily.");
        verify_no_scheduling_hallucination(&mut r, &[]);
        assert!(r.starts_with("⚠️"));
        assert!(r.contains("not actually invoked"));
    }

    #[test]
    fn scheduling_skips_when_no_claim_phrase() {
        let mut r = String::from("I see a task in the dashboard, but I didn't make it.");
        verify_no_scheduling_hallucination(&mut r, &[]);
        // not a claim phrase → unchanged
        assert!(!r.contains("Correction"));
    }

    #[test]
    fn quality_usable_for_real_report() {
        let body = "a".repeat(200);
        let q = classify_response_quality(&body, 100);
        assert_eq!(q, ResponseQuality::Usable);
        assert!(q.is_usable());
    }

    #[test]
    fn quality_empty_when_all_think() {
        let q = classify_response_quality("<think>secret</think>", 100);
        assert_eq!(q, ResponseQuality::Empty);
        assert!(!q.is_usable());
    }

    #[test]
    fn quality_malformed_xml() {
        // dominant <execute_tool> body
        let body = "<execute_tool>noo_inference{prompt:\"x\", max_tokens:4096}</execute_tool>";
        let q = classify_response_quality(body, 10);
        assert_eq!(q, ResponseQuality::Malformed);
    }

    #[test]
    fn quality_too_short() {
        let q = classify_response_quality("short", 100);
        match q {
            ResponseQuality::TooShort { chars: 5, min: 100 } => {}
            other => panic!("expected TooShort, got {:?}", other),
        }
    }

    #[test]
    fn quality_length_measured_on_visible_not_raw() {
        // Latent-bug case: 5KB of <think> hides a 5-char visible reply.
        // Raw length passes 100, but visible doesn't — should be TooShort.
        let big_think = "x".repeat(5000);
        let body = format!("<think>{big_think}</think>hello");
        let q = classify_response_quality(&body, 100);
        assert!(matches!(q, ResponseQuality::TooShort { chars: 5, min: 100 }));
    }

    #[test]
    fn quality_stall_narration_long_enough_but_no_content() {
        // Real-world case from 2026-06-08: 1700-char response that's
        // all "I have gathered" / "I will now synthesize" with no
        // headers/bullets. Should be StallNarration even though it
        // passes the length floor.
        let body = "I have gathered all the necessary information from the \
                    knowledge base and external sources. I will now synthesize \
                    these findings into a comprehensive report covering the \
                    requested topic. The synthesis process will include \
                    cross-referencing primary sources, identifying key trends, \
                    and structuring the analysis. I am compiling the data into \
                    a structured format. The next step is to finalize the \
                    presentation. I will provide the complete report shortly \
                    once compilation is complete and the synthesis process \
                    finishes. The report will cover the main themes identified.";
        // Pad it past the threshold
        let padded = body.repeat(3);
        let q = classify_response_quality(&padded, 1500);
        assert_eq!(q, ResponseQuality::StallNarration, "actual: {q:?}");
    }

    #[test]
    fn quality_real_report_passes_despite_narration_phrases() {
        // A real report may include "I will now examine X" preamble.
        // As long as it has structural markers (headers/bullets), it
        // should NOT be flagged as a stall.
        let real = "## Summary\n\n\
                    I will now examine the field of agentic AI in 3D worlds.\n\n\
                    ## Key Findings\n\n\
                    - First finding with detail\n\
                    - Second finding with detail\n\
                    - Third finding with detail\n\
                    - Fourth finding with detail\n\n\
                    ## Details\n\n\
                    More content here that I have gathered from sources.";
        let q = classify_response_quality(real, 100);
        assert_eq!(q, ResponseQuality::Usable);
    }

    #[test]
    fn min_chars_per_action() {
        assert_eq!(min_chars_for_action("research_report"), 1500);
        assert_eq!(min_chars_for_action("research_and_send"), 1500);
        assert_eq!(min_chars_for_action("daily_briefing"), 600);
        assert_eq!(min_chars_for_action("cluster_health"), 100);
        assert_eq!(min_chars_for_action("unknown_action"), 100);
    }

    #[test]
    fn min_chars_scales_with_depth() {
        // A 'deep' report needs a much higher floor than 'brief' so short
        // deep reports get rejected instead of delivered.
        assert_eq!(min_chars_for_action_depth("research_report", Some("brief")), 1500);
        assert_eq!(min_chars_for_action_depth("research_report", Some("standard")), 2500);
        assert_eq!(min_chars_for_action_depth("research_and_send", Some("deep")), 4000);
        assert_eq!(min_chars_for_action_depth("research_report", Some("exhaustive")), 6000);
        // Missing depth → standard floor.
        assert_eq!(min_chars_for_action_depth("research_report", None), 2500);
        // Non-research actions ignore depth, keep their flat floor.
        assert_eq!(min_chars_for_action_depth("daily_briefing", Some("deep")), 600);
        assert_eq!(min_chars_for_action_depth("cluster_health", None), 100);
    }

    #[test]
    fn validation_error_counted() {
        let calls = vec![json!({
            "name": "noo_inference",
            "result": {
                "success": false,
                "output": "Worker error: 1 validation error for PaiInference\nprompt\n  Field required [type=missing, input_value={}, input_type=dict]",
                "error": "Worker unavailable",
            }
        })];
        assert_eq!(count_validation_errors(&calls), 1);
    }

    #[test]
    fn validation_error_skipped_on_success() {
        let calls = vec![json!({
            "name": "web_search",
            "result": {"success": true, "output": "5 results", "error": null}
        })];
        assert_eq!(count_validation_errors(&calls), 0);
    }

    #[test]
    fn tool_error_hidden_by_success_claim() {
        let calls = vec![json!({
            "name": "noo_heartbeat_run_task",
            "result": {
                "success": false,
                "output": "",
                "error": "NATS request failed: request timed out",
            }
        })];
        assert!(detect_tool_error_hidden_by_success_claim(
            "The daily agent self-check has been triggered successfully.",
            &calls
        ));
    }

    #[test]
    fn tool_error_honest_failure_report_skipped() {
        // Tool failed AND model said so — not a hallucination.
        let calls = vec![json!({
            "name": "noo_heartbeat_run_task",
            "result": {
                "success": false,
                "output": "",
                "error": "NATS request failed: request timed out",
            }
        })];
        assert!(!detect_tool_error_hidden_by_success_claim(
            "Tool returned an error: request timed out. Please retry.",
            &calls
        ));
    }

    #[test]
    fn tool_error_no_failed_calls_skipped() {
        let calls = vec![json!({
            "name": "web_search",
            "result": {"success": true, "output": "results", "error": null}
        })];
        // Even with a success claim, no failed call = no hallucination.
        assert!(!detect_tool_error_hidden_by_success_claim(
            "Successfully ran the search.",
            &calls
        ));
    }
}
