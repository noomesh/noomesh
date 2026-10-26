// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Shared helpers for the heartbeat scheduler.
//!
//! - `build_action_prompt`: prompt template per heartbeat action. Used by
//!   both the cron-tick loop (`heartbeat_loop.rs`) and the manual run-now
//!   route (`routes/intelligence.rs::heartbeat_run_task`) so they stay in
//!   sync — previously these had drifted as separate copies.
//! - `resolve_tz` / `compute_next_run`: TZ-aware cron evaluation. The
//!   heartbeat scheduler defaults to `America/New_York` so user-entered
//!   schedules like `0 8 * * *` mean "8 AM ET" rather than UTC. Override
//!   via the `NOO_HEARTBEAT_TZ` env var (any IANA name).
//! - `notify_channels`: dispatches result text (or a file artifact) to
//!   each `(channel, recipient)` configured on the task by POSTing to
//!   `/api/channels/send` — the native Rust route
//!   (`routes::communication::channels_send` → `send_channel_message`,
//!   SA OAuth2 via `google_auth`). The Python channel engine this used to
//!   reach is retired.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use cron::Schedule;
use serde_json::{json, Value};
use sqlx::Row;

/// Threshold above which the result text is sent as a `.md` attachment
/// instead of being embedded inline in the chat message. Picked
/// generously — Google Chat's text limit is 4096 chars, and we want
/// headroom for any prefix the adapter adds.
pub const FILE_ATTACH_CHAR_THRESHOLD: usize = 3500;

/// Strip stray reasoning tags that leak into user-facing text from the
/// streaming accumulator. Gemma's reasoning_parser consumes the open
/// `<think>` but if the model emits an unmatched `</think>` (or the
/// parser misses a paired block), it ends up at the start of the
/// content. Defense-in-depth: also strip any complete `<think>...</think>`
/// blocks left in the body, and trim leading whitespace.
pub fn sanitize_result_text(text: &str) -> String {
    // gemma-4's untagged reasoning first: a report is saved and sent from
    // its first heading, never with the model's planning as its body.
    let mut s = crate::verify::response::strip_gemma_thought(text);
    // Remove paired blocks first (greedy across newlines via DOTALL flag).
    let re = regex::Regex::new(r"(?s)<think>.*?</think>\s*").unwrap();
    s = re.replace_all(&s, "").to_string();
    // Remove a stray leading closer that has no matching opener.
    let trimmed = s.trim_start();
    if let Some(rest) = trimmed.strip_prefix("</think>") {
        s = rest.trim_start().to_string();
    } else {
        s = trimmed.to_string();
    }
    // Strip an UNTAGGED leading reasoning preamble. Some models (gemma-4 with
    // no reasoning parser, or any model prompted to "plan") narrate their
    // planning as plain prose *before* the deliverable — neither the <think>
    // strip above nor the gemma `thought\n` virtual-open catches that free
    // form CoT, so it leaks into saved/sent reports. If the output has a real
    // markdown heading and the text before it reads like first-person
    // planning, drop that preamble.
    strip_leading_reasoning_preamble(&s)
}

/// Remove a leading first-person planning/reasoning block that precedes the
/// first markdown heading. Deliberately conservative: only fires when a real
/// heading exists, non-trivial text precedes it, and that text is
/// reasoning-heavy (≥2 distinct planning markers). This never eats a short
/// legitimate intro line, and no-ops when the report already starts with its
/// title.
fn strip_leading_reasoning_preamble(s: &str) -> String {
    // Byte offset of the first markdown heading line (`^\s*#{1,6} `).
    let mut offset = 0usize;
    let mut heading_start: Option<usize> = None;
    for line in s.split_inclusive('\n') {
        let t = line.trim_start();
        let hashes = t.bytes().take_while(|&b| b == b'#').count();
        if (1..=6).contains(&hashes) && t.as_bytes().get(hashes) == Some(&b' ') {
            heading_start = Some(offset);
            break;
        }
        offset += line.len();
    }
    let Some(hs) = heading_start else { return s.to_string() };
    if hs == 0 {
        return s.to_string(); // already starts with the title — nothing to strip
    }
    let preamble = &s[..hs];
    if preamble.trim().len() <= 40 {
        return s.to_string(); // too short to be a leaked CoT; keep it
    }
    let lower = preamble.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "the user", "let me", "let's", "i need to", "i should", "i'll",
        "i will", "i am mesh", "i can use", "my plan", "plan:", "okay,",
        "wait,", "first, i", "i must", "here's my plan", "i have data",
        "i have enough", "thought\n", "thought:", "let's write", "let me write",
        "as mesh", "let me start", "i'll aim", "let me draft", "let's draft",
    ];
    let hits = MARKERS.iter().filter(|m| lower.contains(**m)).count();
    if hits >= 2 {
        s[hs..].to_string()
    } else {
        s.to_string()
    }
}

/// Actions that the Rust coordinator runs natively via the LLM
/// agentic loop with curated prompts (depth-spec, discipline skill,
/// drive upload). Everything ELSE has a real Python implementation in
/// `noomesh.gateway.heartbeat._dispatch` that does data gathering /
/// graph work / maintenance — those go via NATS to Python instead of
/// hoping the LLM decides to call the right MCP tool.
///
/// Keeping this list small + explicit so it's obvious when a new action
/// is added: pick a side. LLM-driven actions need a prompt template in
/// `build_action_prompt_inner`; system actions just need a Python
/// handler in `heartbeat.py`.
const RUST_LLM_ACTIONS: &[&str] = &[
    "research_report",
    "research_and_send",
    "custom_prompt",
    "daily_briefing",
    "chat_digest",
    "conversation_summarize",
    "news_scan",
    // Ported 2026-08-01. Python's `_channel_message` generated the text
    // fine but delivered it over an HTTP loopback to
    // `POST /api/channels/send` carrying only an mTLS cert and no cluster
    // HMAC bearer — so the gateway 401'd its own call and every send
    // failed (daily_digest_gchat, silently `status=success` until the
    // 29th). Rust reaches `send_channel_message` in-process, so the
    // loopback and its auth gap are gone.
    "channel_message",
    // Tier B per the design, ported 2026-08-12: pure prompt-builder —
    // the Python handler formatted the configured goals into a bullet
    // list and ran the coordinator; that is exactly this path. The
    // no-goals case short-circuits in the loop (goal_review_no_goals),
    // matching Python's non-LLM early return.
    "goal_review",
];

/// System actions ported from Python to Rust. These are pure
/// orchestration / DB queries / HTTP calls — no ML libraries — so per
/// the project's Rust/Python split rule (ML stays Python, everything
/// else Rust), they belong on this side. The Python equivalents in
/// `heartbeat.py::_dispatch` become dead code once these all land.
///
/// NOTE: this list is the *allowlist*, not the inventory. `action_path()`
/// sends everything not named here (or in `RUST_LLM_ACTIONS`) to Python via
/// the `else` branch, so the Python-delegated set is 22 actions — not the
/// three this comment used to claim. Most of them are pure orchestration and
/// delegate only because nobody enumerated them.
const RUST_NATIVE_ACTIONS: &[&str] = &[
    "cluster_health",
    "cost_report",
    "security_audit",
    "memory_cleanup",
    "idle_scaledown",
    "agent_self_check",
    "disk_cleanup",
    // Tier A per the design: gateway HTTP reads + a file write, no ML.
    "write_log",
    // Ported 2026-08-01: a spool file write + a poll, no ML — it never
    // belonged on the Python side of the split.
    "database_backup",
    // Cert actions: PARSING only in Rust. Rotation itself runs host-side
    // via the watcher spool, so no signing crate is involved.
    "cert_rotation_check",
    "cert_auto_rotate",
    // Retention for noo_heartbeat_runs. Two SQL statements, no ML. Added
    // 2026-08-03: the retention code had existed and been correct for months
    // with NOTHING scheduling it, so the table grew unbounded.
    "heartbeat_retention",
    "agent_messages_retention",
    // Export-then-drop for noo_security_audit partitions past the retention
    // window. It lived only in Python, behind a scheduler that does not run
    // in production, so no audit partition was ever rotated. SQL + a JSONL
    // file write on /data, no ML. See audit_partition.rs.
    "audit_log_rotate",
    // Retention for noo_token_usage: roll expired raw partitions into the
    // monthly table, then drop them. SQL only, no ML.
    "usage_rollup",
    // Tier C by the design's list, but MIS-TIERED — the THIRD name-based
    // mis-tier (write_log, rag_reindex, now this): the body is three SQL
    // SELECTs and JSONL file writes, no ML anywhere. Ported 2026-08-12.
    "backup_knowledge",
    // The LAST Tier C port: staged graph hygiene was ~95% SQL
    // around difflib's Ratcliff–Obershelp ratio — see graph_prune.rs for
    // the full semantics inventory (advisory lock, staging, budget).
    "graph_prune",
    // The scheduled junk-entity cleanup: the route's core (`entity_cleanup_task.rs`).
    // New, so there is no Python body at all. Its `apply` is a person's decision,
    // recorded on the task row; see that module.
    "entity_cleanup",
    // Tier C by the design's list, but MIS-TIERED like write_log: the
    // Python body was two loopback HTTP calls — GET /api/v1/rag/status
    // and POST /api/v1/rag/embed — and the second endpoint does not
    // exist in the Rust gateway, so the handler has errored on every
    // scheduled run since the port. The honest implementation counts
    // the unembedded backlog (shared SQL with the autonomy evaluator)
    // and submits a background_embed job; the actual embedding rides
    // the existing NATS job path to trellion, exactly the design's
    // Rust-owns-policy / NATS-carries-ML shape. 2026-10-10: that job
    // (background_embed) is retired — it drained conversation memory, not
    // pages, and trellion embeds pages itself — so the action now checks
    // the backlog DRAINS and raises when it does not.
    "rag_reindex",
    // Tier B per the design, ported 2026-08-12. Not a single prompt —
    // a measurement harness (N coordinator calls, latency + keyword
    // scoring) — so it lives on the native path and drives
    // coordinator::run itself, like agent_self_check's retry actions.
    "self_benchmark",
    // Tier A per the design, ported 2026-08-11. Both are pure HTTP:
    // model_cache_warm reads /api/models/cached and POSTs /api/models/pull
    // over the HMAC'd loopback; channel_keepalive probes the channel APIs
    // directly (telegram getMe, google_chat token mint) — an HONEST probe,
    // unlike /api/channels/status which only checks env presence. The
    // Python versions in heartbeat.py::_dispatch are now unreachable.
    "channel_keepalive",
    "model_cache_warm",
];

/// Action path: which side of the Rust/Python split owns this action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionPath {
    /// Build a prompt + run through `coordinator::run` (LLM loop).
    RustLlm,
    /// Rust handler in this file produces the result string directly
    /// (no LLM, just data + formatting).
    RustNative,
    /// NATS-delegate to Python `heartbeat._dispatch` — used for actions
    /// that call into ML subsystems (RAG embedding, graph extraction,
    /// LLM-driven reasoning) that haven't been ported.
    PythonDelegate,
}

/// Decide which path an action takes through the heartbeat loop.
pub fn action_path(action: &str) -> ActionPath {
    if RUST_LLM_ACTIONS.contains(&action) {
        ActionPath::RustLlm
    } else if RUST_NATIVE_ACTIONS.contains(&action) {
        ActionPath::RustNative
    } else {
        ActionPath::PythonDelegate
    }
}

/// Python-delegated actions whose handlers need the trellion ML pack
/// (PageIndex store, graph services, recall memory). These
/// dispatch on `worker.api.heartbeat.run_ml` (trellion-gated, see
/// `addons::is_trellion_subject`) instead of the core dispatch shell,
/// which has no ML tree and would answer with a success-shaped
/// "not available" no-op. Enumerated from the handlers' actual service
/// usage — not the design's "two surviving ML actions", which missed
/// graph_prune, knowledge_refresh, and graph_clustering.
pub const TRELLION_ACTIONS: &[&str] = &[
    "graph_clustering",
    // graph_prune is NOT here: it went Rust-native (three SQL statements,
    // the mis-tier fix) and action_path() short-circuits to
    // RustNative before this list is consulted. Its stale entry here was
    // the first catch of tests/test_heartbeat_ml_action_parity.py.
    "graph_signals",
    "knowledge_refresh",
    "thought_experiment",
];

/// True when the action must run on the trellion worker (ML surfaces).
pub fn is_trellion_action(action: &str) -> bool {
    TRELLION_ACTIONS.contains(&action)
}

/// Returns true if the action should run through the Rust coordinator's
/// LLM loop (with curated prompt + skill + drive upload). Kept for
/// callers that haven't migrated to ``action_path()``.
pub fn is_llm_driven_action(action: &str) -> bool {
    RUST_LLM_ACTIONS.contains(&action)
}

/// A `channel_message` task may carry a literal `config.message` instead
/// of a `config.prompt`. The literal IS the payload — running an
/// operator's exact words through the model would rewrite them — so this
/// short-circuits the LLM loop and exempts the text from the usability
/// gate (a deliberate one-line message is not a failed report).
pub fn literal_channel_message(action: &str, config: &Value) -> Option<String> {
    if action != "channel_message" {
        return None;
    }
    config
        .get("message")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// `goal_review` with no goals needs no model — Python returned the plain
/// text without an LLM call, and burning a coordinator run to restate an
/// empty config would be waste. Returns the exact Python message.
pub fn goal_review_no_goals(action: &str, config: &Value) -> Option<String> {
    if action != "goal_review" {
        return None;
    }
    let empty = config
        .get("goals")
        .and_then(|v| v.as_array())
        .map(|a| a.is_empty())
        .unwrap_or(true);
    empty.then(|| "Goal review: no goals configured.".to_string())
}

/// Validate a `channel_message` task before it runs. Python raised on a
/// missing destination and returned a "no message or prompt configured"
/// string; both must surface as a recorded `error`, not a success with a
/// complaint in the body. Returns `Some(reason)` when the task is
/// unrunnable.
pub fn channel_message_config_error(
    action: &str,
    config: &Value,
    channels: &Value,
) -> Option<String> {
    if action != "channel_message" {
        return None;
    }
    let has_column_target = channels
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v.as_str().is_some_and(|s| !s.is_empty())));
    let has_config_target = config
        .get("channel")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
        && config
            .get("recipient")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty());
    if !has_column_target && !has_config_target {
        return Some(
            "config.channel and config.recipient are required. For Google Chat, \
             recipient is the space name (e.g. 'spaces/AAAAxxxx')."
                .to_string(),
        );
    }
    let has_prompt = config
        .get("prompt")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty());
    if !has_prompt && literal_channel_message(action, config).is_none() {
        return Some("no message or prompt configured".to_string());
    }
    None
}

/// Decide whether a heartbeat task's result should be dispatched as a
/// file attachment regardless of length. Currently triggers when:
/// - the action name contains `report` (research_report, cost_report,
///   research_and_send) — anything labelled as a "report" should be a
///   file the user can save/share, not an inline chat blob;
/// - or the task's config has `attach_as_file: true` (explicit opt-in
///   for non-report actions like `daily_briefing` or `write_log`);
/// - or the legacy `save_to_file: true` flag is set.
/// The chat text that carries a report to a channel.
///
/// With a Drive link, a one-line pointer. Without one, the report ITSELF —
/// every adapter splits long text into platform-sized chunks, and none of
/// them attaches a file: the Google Chat path deliberately ignores
/// `file_path` (cross-identity wall, see `send_google_chat`), Telegram and
/// WhatsApp never read it. Until 2026-09-28 this branch said "Full report
/// attached (N chars)" and sent only that line, so a report with no Drive
/// folder configured reached the operator as a claim of delivery and
/// nothing else.
pub(crate) fn report_delivery_message(
    task_name: &str,
    result_text: &str,
    drive_link: Option<&str>,
) -> String {
    match drive_link {
        Some(link) => format!(
            "Heartbeat task '{task_name}' completed ({chars} chars). \
             Full report: {link}",
            chars = result_text.len()
        ),
        None => result_text.to_string(),
    }
}

fn should_force_file_attachment(action: &str, config: &Value) -> bool {
    if action.contains("report") || action == "research_and_send" {
        return true;
    }
    if config.get("attach_as_file").and_then(|v| v.as_bool()).unwrap_or(false) {
        return true;
    }
    if config.get("save_to_file").and_then(|v| v.as_bool()).unwrap_or(false) {
        return true;
    }
    false
}

/// Resolve the heartbeat scheduler timezone from the `NOO_HEARTBEAT_TZ`
/// env var. Defaults to `America/New_York` so user-edited schedules
/// match the user's local clock without extra config.
pub fn resolve_tz() -> Tz {
    // Config-graduation phase 2: noo_settings DB row (hot-reloadable via
    // POST /api/heartbeat/reload) → env NOO_HEARTBEAT_TZ → yaml
    // heartbeat.tz → America/New_York.
    crate::settings::get("NOO_HEARTBEAT_TZ")
        .filter(|v| !v.is_empty())
        .or_else(|| crate::config::global().heartbeat.tz.clone().filter(|v| !v.is_empty()))
        .and_then(|s| s.parse::<Tz>().ok())
        .unwrap_or(chrono_tz::America::New_York)
}

/// Compute the next fire time after `from` for a cron expression,
/// interpreting the cron in `tz`. The result is returned as UTC for
/// storage in `noo_heartbeat_tasks.next_run` (which is `TIMESTAMPTZ`).
pub fn compute_next_run(cron_expr: &str, from: DateTime<Utc>, tz: Tz) -> Option<DateTime<Utc>> {
    let schedule = parse_cron(cron_expr).ok()?;
    let local_from = from.with_timezone(&tz);
    schedule
        .after(&local_from)
        .next()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Parse a cron expression exactly as the scheduler does (normalised to the
/// `cron` crate's form first). The error is the parser's own reason, so a
/// route that refuses a bad schedule can say why. `compute_next_run` and the
/// schedule-edit route both go through here, so what the route accepts is
/// what the scheduler can fire.
pub fn parse_cron(cron_expr: &str) -> Result<Schedule, String> {
    Schedule::from_str(&normalize_cron(cron_expr)).map_err(|e| e.to_string())
}

/// Normalize a cron expression to the 6/7-field form the `cron` crate
/// expects. The Python side uses `croniter` which accepts 5-field
/// expressions (the standard) — we prepend "0 " for seconds=0 to keep
/// the two engines compatible, and translate the day-of-week field
/// from Unix to Quartz numbering (see `translate_unix_dow`).
fn normalize_cron(expr: &str) -> String {
    let trimmed = expr.trim();
    let fields: Vec<&str> = trimmed.split_whitespace().collect();
    match fields.len() {
        5 => format!(
            "0 {} {} {} {} {}",
            fields[0],
            fields[1],
            fields[2],
            fields[3],
            translate_unix_dow(fields[4]),
        ),
        _ => trimmed.to_string(),
    }
}

/// Translate a Unix cron day-of-week field (0-7 where 0/7 = Sunday,
/// 1 = Monday) to the `cron` crate's Quartz-style numbering (1-7 where
/// 1 = Sunday). Everything else in the system — croniter on the Python
/// side, the dashboard, and user expectations — uses Unix numbering;
/// without this shift `0 9 * * 1` ("Monday 9am") silently fires on
/// SUNDAY (observed 2026-06-12: weekly_research and the 1-5 weekday
/// digest both seated one day early).
///
/// Numeric tokens shift +1 (0→1, 1→2, …, 6→7, 7→1); `*`/`?` and name
/// tokens (MON, FRI, …) pass through — names mean the same day in both
/// dialects. Handles lists, ranges, and step suffixes. Wraparound
/// numeric ranges (e.g. `6-0`) are not supported — none exist in
/// practice and croniter-side validation discourages them.
fn translate_unix_dow(field: &str) -> String {
    let shift = |tok: &str| -> String {
        match tok.parse::<u8>() {
            Ok(n) if n == 0 || n >= 7 => "1".to_string(),
            Ok(n) => (n + 1).to_string(),
            Err(_) => tok.to_string(), // *, ?, or day names
        }
    };
    field
        .split(',')
        .map(|part| {
            let (range, step) = match part.split_once('/') {
                Some((r, s)) => (r, Some(s)),
                None => (part, None),
            };
            let shifted = range
                .split('-')
                .map(shift)
                .collect::<Vec<_>>()
                .join("-");
            match step {
                Some(s) => format!("{shifted}/{s}"),
                None => shifted,
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Owner written to `noo_conversations.user_id` for every conversation a
/// heartbeat task creates.
///
/// This is a pseudo-user, deliberately absent from `noo_users`: heartbeat
/// output is operational history, not any person's data, and attributing it to
/// a human would make it vanish on that human's erasure.
///
/// It exists because attribution used to happen only *after the fact*, by
/// `backfill-conversation-user.sh` (a retired one-shot) recomputing the deterministic
/// conversation UUIDs from `noo_heartbeat_tasks` + `noo_heartbeat_runs`. That
/// recompute is a treadmill — it has to be re-run forever, and it silently
/// stops working for any run whose inputs are gone (retention, a task delete
/// cascade, or an id-scheme change). Labelling at write time makes the
/// recompute a one-off repair for pre-existing rows instead of the mechanism.
///
/// `session::save_message` COALESCEs on conflict, so this never overwrites an
/// existing attribution — it only fills a NULL.
///
/// The value must stay in step with `--internal-label` in that script; the two
/// are compared by the follow-up 32 verification query.
pub const HEARTBEAT_CONVERSATION_OWNER: &str = "system:heartbeat";

/// Decide whether a heartbeat task should reuse a stable `conversation_id`
/// across runs (so layers B + C of the ABC context system can accumulate
/// thematic summary + semantic recall across firings) or get a fresh
/// per-run `conversation_id` (so a point-in-time snapshot doesn't get
/// polluted by last week's data).
///
/// Defaults are by action type:
/// - **Stable** (narrative/research, benefits from continuity):
///   `research_report`, `write_log`, `custom_prompt`
/// - **Per-run** (snapshots, prior context would mislead):
///   `daily_briefing`, `cluster_health`, `cost_report`, `security_audit`,
///   and any unknown action
///
/// Override per-task via `task.config.stable_conversation` (bool).
pub fn build_conversation_id(
    task_id: &str,
    run_id: &str,
    action: &str,
    config: &Value,
) -> String {
    let default_stable = matches!(
        action,
        "research_report" | "research_and_send" | "write_log" | "custom_prompt"
    );
    let stable = config
        .get("stable_conversation")
        .and_then(|v| v.as_bool())
        .unwrap_or(default_stable);
    if stable {
        format!("heartbeat-{task_id}")
    } else {
        format!("heartbeat-{task_id}-{run_id}")
    }
}

/// Candidate paths for skill markdown files. Mirrors the lookup
/// `routes/settings.rs` uses for the prompt-skills inventory.
const SKILL_DIR_CANDIDATES: &[&str] = &[
    "/app/prompts/skills/core",
    "/app/prompts/skills/evolved",
    "prompts/skills/core",
    "prompts/skills/evolved",
];

/// Load the *body* (not the YAML frontmatter) of a skill markdown file
/// by name. Returns `None` if the file isn't found or can't be read.
///
/// Used by `build_action_prompt` to prepend opt-in skill text (e.g.
/// `heartbeat-discipline`) to the action prompt so heartbeat tasks
/// can share quality rules without each action handler restating them.
pub(crate) fn load_skill_body(name: &str) -> Option<String> {
    let filename = format!("{name}.md");
    for dir in SKILL_DIR_CANDIDATES {
        let path = std::path::Path::new(dir).join(&filename);
        if let Ok(text) = std::fs::read_to_string(&path) {
            // Strip YAML frontmatter (---\n...\n---\n) if present.
            let body = if text.starts_with("---\n") || text.starts_with("---\r\n") {
                text[3..]
                    .find("\n---")
                    .map(|end| text[3 + end + 4..].trim_start().to_string())
                    .unwrap_or(text)
            } else {
                text
            };
            return Some(body);
        }
    }
    None
}

/// Build a prompt for the coordinator from a heartbeat task action.
/// Single source of truth — both the cron-tick loop and the manual
/// run-now route call this.
///
/// If `config.skill` is set (e.g. `"heartbeat-discipline"`), the named
/// skill's body is loaded from `prompts/skills/` and prepended to the
/// action's own prompt. This lets tasks opt into shared quality rules
/// without baking them into each per-action template.
pub fn build_action_prompt(action: &str, task_name: &str, config: &Value) -> String {
    let action_prompt = build_action_prompt_inner(action, task_name, config);

    // Opt-in skill prepend. Two fields supported:
    //   - "skill": "name"           → single skill
    //   - "skills": ["a", "b"]      → multiple, joined in order
    let mut skill_names: Vec<String> = Vec::new();
    if let Some(s) = config.get("skill").and_then(|v| v.as_str()) {
        if !s.is_empty() {
            skill_names.push(s.to_string());
        }
    }
    if let Some(arr) = config.get("skills").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    skill_names.push(s.to_string());
                }
            }
        }
    }

    if skill_names.is_empty() {
        return action_prompt;
    }

    let mut parts: Vec<String> = Vec::with_capacity(skill_names.len() + 1);
    for name in &skill_names {
        match load_skill_body(name) {
            Some(body) => parts.push(body),
            None => tracing::warn!(skill = %name, "heartbeat_skill_not_found"),
        }
    }
    if parts.is_empty() {
        return action_prompt;
    }
    parts.push(format!("---\n\n# Task\n\n{action_prompt}"));
    parts.join("\n\n")
}

/// Ingest a finished research report into the local PageIndex KB so
/// subsequent runs (and ad-hoc `noo_rag_query` calls) can find it.
/// Best-effort: failures log a warning but don't propagate — the
/// report has already been generated and delivered to channels;
/// missing KB ingest is non-fatal.
///
/// Without this, daily research reports go to Drive but never re-enter
/// the knowledge base the coordinator queries — which is the root
/// cause of the "every essay looks the same" problem (the model has
/// no in-KB record of what it wrote yesterday).
pub async fn ingest_report_to_kb(
    state: &crate::state::AppState,
    task_id: &str,
    task_name: &str,
    action: &str,
    run_id: &str,
    result_text: &str,
) {
    // Skip non-research actions and trivially short outputs.
    if !matches!(action, "research_report" | "research_and_send") {
        return;
    }
    if result_text.chars().count() < 400 {
        return;
    }

    let title = format!("Heartbeat report: {task_name} ({run_id})");
    // `source_uri` — NOT `source`. They are different fields: the worker
    // reads `source_uri` for the docs column that dedup and the kb_roles
    // globs both key on, while `source` is a free label it does not persist
    // there. This sent only `source`, so every report landed with an EMPTY
    // source_uri: no dedup key, no provenance for the role rules, and the
    // per-run traceability this comment claimed never existed. 29 reports on
    // the controller, all of them sourceless (measured 2026-08-16).
    let source_uri = format!("heartbeat://{task_id}/{run_id}");
    let body = json!({
        "text": result_text,
        "title": title,
        "source": source_uri,
        "source_uri": source_uri,
        // `generated` ALONE, deliberately. It is in nobody's default
        // audience, so these reports leave ordinary retrieval and return only
        // when asked for by name (`roles: ["generated"]`, permitted in
        // kb._resolve_kb_roles). 211 daily notes were out-ranking 74
        // substantive meeting transcripts; a report about the cluster should
        // not answer a question about what the humans said.
        "roles": ["generated"],
    });

    // In process: what `POST /api/v1/docs/ingest` does for
    // a JSON body with no requester context — the same worker call — without
    // an HTTPS self-call signed with the controller HMAC. `_requester` is
    // absent from this body, so the worker reads it as an internal caller,
    // exactly as it did for the HMAC'd request.
    match state.memory().kb_ingest(&body).await {
        Ok(_) => {
            tracing::info!(
                task_id = %task_id,
                run_id = %run_id,
                source = %source_uri,
                "heartbeat_report_ingested_to_kb"
            );
        }
        Err(e) => {
            tracing::warn!(
                task_id = %task_id,
                run_id = %run_id,
                error = %format!("Worker unavailable: {e}"),
                "heartbeat_report_kb_ingest_failed"
            );
        }
    }
}

/// For research-style heartbeat actions (research_report,
/// research_and_send), append a "prior research" block listing the
/// gist of the last N prior runs, framed as a cumulative body of work:
/// the model reviews what earlier reports established, identifies the
/// open threads they left, and researches new aspects / extensions of
/// those findings. No-op for any other action and for tasks with no
/// prior successful runs.
///
/// This is the fix for "every daily research report looks the same" —
/// the base prompt has no awareness of prior coverage; the model can't
/// build on work it can't see. Deliberately framed as "extend the
/// research" rather than "do not repeat": prohibition framing made the
/// model dodge its own strongest threads instead of deepening them.
pub async fn enrich_research_prompt_with_history(
    base_prompt: String,
    db: &sqlx::PgPool,
    action: &str,
    task_id: &str,
) -> String {
    if !matches!(action, "research_report" | "research_and_send") {
        return base_prompt;
    }
    let priors = fetch_prior_research_summaries(db, task_id, 3).await;
    if priors.is_empty() {
        return base_prompt;
    }

    // Most recent prior run (priors are ordered DESC) — used to give the
    // model a concrete recency cutoff instead of a made-up example date.
    let latest_prior = search_cutoff(priors[0].0, Utc::now()).format("%Y-%m-%d").to_string();

    let mut block = String::from(
        "\n\n---\n\n\
         **📚 PRIOR RESEARCH ON THIS TASK — REVIEW, THEN EXTEND.** This \
         task is cumulative: each run builds on the body of research below \
         rather than restating it. Treat these earlier findings as \
         established ground you are extending.\n\n",
    );
    for (when, summary) in &priors {
        block.push_str(&format!(
            "- **{}** — {}\n",
            when.format("%Y-%m-%d"),
            summary
        ));
    }
    block.push_str(&format!(
        "\n**How to extend the research this run:**\n\
         1. Review the prior findings above and identify the open threads \
            they left: unanswered questions, claims worth verifying or \
            challenging, developments that have likely moved since, and \
            adjacent areas the earlier reports touched but didn't explore.\n\
         2. Pick a small number of those threads as this run's focus and \
            research them in depth — new aspects, extensions, second-order \
            effects, downstream consequences, or fresh developments that \
            postdate the latest report (use web_search with explicit date \
            filters, e.g. `after:{latest_prior}`, so results are newer than \
            the prior coverage).\n\
         3. Entities and systems already covered above are context, not \
            headlines: build on them, compare new findings against them, and \
            report what has *changed* about them — the new material is the \
            deliverable.\n\
         4. Open your Summary with one sentence naming which prior thread(s) \
            this report extends and what it adds to the body of research.",
    ));
    format!("{base_prompt}{block}")
}

/// The `after:` date a research run searches from.
///
/// "Newer than the last report" is right on the weekly schedule, but a
/// manual run the day before made it `after:<yesterday>` — a window that
/// mostly finds nothing (2026-10-01: one of six searches came back empty).
/// So the cutoff is the last report's date or `RESEARCH_MIN_WINDOW_DAYS`
/// ago, whichever is EARLIER: a recent run can never shrink the window.
fn search_cutoff(latest_prior: DateTime<Utc>, now: DateTime<Utc>) -> DateTime<Utc> {
    latest_prior.min(now - chrono::Duration::days(RESEARCH_MIN_WINDOW_DAYS))
}

const RESEARCH_MIN_WINDOW_DAYS: i64 = 30;

/// A prior run shorter than this, once cleaned, is not a report to extend.
const PRIOR_MIN_CHARS: usize = 1500;

async fn fetch_prior_research_summaries(
    db: &sqlx::PgPool,
    task_id: &str,
    limit: i64,
) -> Vec<(DateTime<Utc>, String)> {
    let rows_res = sqlx::query(
        "SELECT started_at, result_text \
         FROM noo_heartbeat_runs \
         WHERE task_id = $1 \
           AND status = 'success' \
           AND result_text IS NOT NULL \
           AND length(result_text) > 200 \
         ORDER BY started_at DESC \
         LIMIT $2",
    )
    .bind(task_id)
    // Junk runs are filtered below, so read past them: the newest `limit`
    // rows may be exactly the ones that do not count.
    .bind(limit * 4)
    .fetch_all(db)
    .await;

    let rows = match rows_res {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                task_id = %task_id,
                error = %e,
                "fetch_prior_research_summaries_failed"
            );
            return Vec::new();
        }
    };

    let rows: Vec<(DateTime<Utc>, String)> = rows
        .into_iter()
        .filter_map(|row| Some((row.try_get("started_at").ok()?, row.try_get("result_text").ok()?)))
        .collect();
    usable_prior_summaries(rows, limit as usize)
}

/// The newest `limit` prior runs that are real reports, summarised.
///
/// A run recorded as success before the quality gate judged gemma's
/// reasoning — a "report" that was 1,041 `thought` lines, or the model's
/// planning — is not findings. Fed forward, its summary read "thought" and
/// the next run built on it (weekly_research, 2026-09-29). Each row is
/// cleaned and judged as a deliverable, exactly as a new run is.
fn usable_prior_summaries(rows: Vec<(DateTime<Utc>, String)>, limit: usize) -> Vec<(DateTime<Utc>, String)> {
    rows.into_iter()
        .filter_map(|(when, text)| {
            let text = sanitize_result_text(&text);
            if !crate::verify::response::classify_response_quality(&text, PRIOR_MIN_CHARS).is_usable() {
                return None;
            }
            let summary = summarize_prior_report(&text);
            (!summary.is_empty()).then_some((when, summary))
        })
        .take(limit)
        .collect()
}

/// Extract a useful gist of a prior report for the "previously
/// covered" block.
///
/// Strategy in order of preference:
/// 1. Find a `## Key Findings` (or similar) section and pull the first
///    3-4 bullet points — these are the *specific* claims, not boilerplate.
/// 2. Fall back to extracting bolded entities (`**Name**`) from the body —
///    these are the named systems/papers/orgs the model identified.
/// 3. Last resort: first prose line (the old behavior).
///
/// Old behavior was step 3 only, which extracted templated opening
/// prose that looked identical across runs and gave the model zero
/// signal about what was actually covered. New behavior surfaces the
/// concrete differentiators so the model can actually pivot.
///
/// Capped at ~400 chars per summary — leaves room for 3-5 prior
/// summaries in the prompt without ballooning the token count.
fn summarize_prior_report(text: &str) -> String {
    if let Some(findings) = extract_findings_section(text) {
        if !findings.is_empty() {
            return findings;
        }
    }
    if let Some(entities) = extract_bolded_entities(text) {
        if !entities.is_empty() {
            return entities;
        }
    }
    // Fallback: first prose line (legacy behavior).
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#')
            || trimmed.starts_with('-') || trimmed.starts_with('*')
        {
            continue;
        }
        let chars: Vec<char> = trimmed.chars().take(400).collect();
        let truncated = trimmed.chars().count() > 400;
        let mut out: String = chars.into_iter().collect();
        if truncated {
            out.push('…');
        }
        return out;
    }
    String::new()
}

/// Find a `## Key Findings` / `## Findings` / `## Summary` section and
/// extract its bullet points or first sentences, capped at ~400 chars.
fn extract_findings_section(text: &str) -> Option<String> {
    const SECTION_HEADERS: &[&str] = &[
        "## Key Findings",
        "## Findings",
        "## Key Points",
        "## Highlights",
        "## Summary",
        "## Executive Summary",
        "## TL;DR",
    ];
    let mut in_section = false;
    let mut collected: Vec<String> = Vec::new();
    let mut total_chars = 0usize;
    for line in text.lines() {
        let trimmed = line.trim();
        if !in_section {
            // Case-insensitive prefix match on the section header.
            let lower = trimmed.to_lowercase();
            if SECTION_HEADERS.iter().any(|h| lower.starts_with(&h.to_lowercase())) {
                in_section = true;
            }
            continue;
        }
        // Stop at the next ## heading.
        if trimmed.starts_with("## ") || trimmed.starts_with("# ") {
            break;
        }
        if trimmed.is_empty() {
            continue;
        }
        // Strip leading bullet markers but keep the content.
        let content = trimmed
            .trim_start_matches("- ")
            .trim_start_matches("* ")
            .trim_start_matches("+ ");
        let preview: String = content.chars().take(180).collect();
        if total_chars + preview.chars().count() > 400 {
            break;
        }
        total_chars += preview.chars().count();
        collected.push(preview);
        if collected.len() >= 4 {
            break;
        }
    }
    if collected.is_empty() {
        None
    } else {
        Some(collected.join(" • "))
    }
}

/// Extract `**Bolded Names**` from the report body. These are typically
/// the specific systems, papers, organizations, or concepts the model
/// chose to highlight — a useful "what was covered" signal even when
/// there's no Findings section.
fn extract_bolded_entities(text: &str) -> Option<String> {
    let mut entities: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut search = text;
    while let Some(start) = search.find("**") {
        let after = &search[start + 2..];
        let end = match after.find("**") {
            Some(i) => i,
            None => break,
        };
        let inner = after[..end].trim();
        // Skip the report's own template fields (**Date:**, **Task ID:**, etc.)
        if !inner.ends_with(':')
            && inner.chars().count() >= 3
            && inner.chars().count() <= 60
            && !seen.contains(inner)
        {
            seen.insert(inner.to_string());
            entities.push(inner.to_string());
        }
        search = &after[end + 2..];
        if entities.len() >= 8 {
            break;
        }
    }
    if entities.is_empty() {
        None
    } else {
        Some(format!("Highlighted: {}", entities.join(", ")))
    }
}

/// Map a `depth` config value (`brief`/`standard`/`deep`/`exhaustive`)
/// to a target length + structure spec injected into the research prompt.
/// Models default to short answers; without an explicit target a "deep"
/// label produces ~1500-char outputs that don't earn their name.
pub(crate) fn depth_to_spec(depth: &str) -> &'static str {
    match depth.to_lowercase().as_str() {
        "brief" => {
            "Length target: ~600-900 words (3500-5500 chars). Hit the headline \
             findings only; one paragraph per section."
        }
        "deep" => {
            // Target kept achievable for a local 12B in one pass — over-large
            // targets (the old 2500-4000 words) make the model narrate "I am
            // compiling the report…" instead of writing it. This still clears
            // the 4000-char `deep` gate with room to spare.
            "Length target: 1000-1600 words (6000-10000 chars). Detailed \
             Analysis must have 3-5 subsections, each with concrete examples, \
             quantitative data where available, and named systems/papers/orgs. \
             Write the full prose directly — surface-level summaries are not \
             acceptable for a 'deep' report."
        }
        "exhaustive" => {
            "Length target: 1800-2800 words (11000-17000 chars). Treat this as \
             a survey: 5-7 Detailed Analysis subsections, explicit methodology \
             notes, comparison tables (markdown), and a Limitations section \
             calling out where evidence was thin."
        }
        // standard / unknown
        _ => {
            "Length target: 800-1300 words (5000-8000 chars). Detailed \
             Analysis should have 3-4 subsections with concrete examples \
             and named systems/papers."
        }
    }
}

pub(crate) fn depth_search_count(depth: &str) -> u8 {
    match depth.to_lowercase().as_str() {
        "brief" => 2,
        "deep" => 4,
        "exhaustive" => 6,
        _ => 3,
    }
}

/// Sourcing rules shared by the single-shot research prompt AND the phased
/// pipeline's gather phase (`research_pipeline`). Tells the model to seek
/// out primary sources (papers/articles) and paraphrase them into original,
/// attributed material rather than dumping quotes — the `{searches}`
/// placeholder is filled per-action by depth. Deliberately says nothing
/// about the SHAPE of the final answer: that differs per caller (full
/// report vs notes + outline) and lives in `RESEARCH_REPORT_DELIVERY` /
/// the pipeline's own gather-output block.
pub(crate) const RESEARCH_SOURCING: &str =
    "Gathering — find NEW external work. web_search is your PRIMARY tool: run \
     {searches} searches with DIFFERENT angles (never repeat a query) to \
     surface RECENT primary sources — papers (arXiv, conference proceedings, \
     journals), official project/lab blogs, and substantive articles — and \
     prefer material published since your last report (use date filters like \
     `after:2026-04`). For each source, note its title, author/venue, and date.\n\n\
     Do NOT use the local knowledge base for findings. `noo_rag_query` returns \
     THIS agent's own past reports and previously-ingested Google Drive papers \
     — leaning on them is exactly the stale repetition to eliminate. Do not \
     call noo_rag_query for sourcing, and NEVER cite a past report or a \
     previously-ingested document as a finding. Every spotlighted finding must \
     be a NEW external source you located via web_search in THIS run; if a \
     paper already appeared in an earlier report, it is not new — skip it.\n\n\
     Write the report in your OWN words: read each source, then paraphrase and \
     synthesise its findings — do NOT copy sentences verbatim. Attribute every \
     non-trivial claim inline to the source it came from (title or URL), and \
     list the full set of references under Sources. The result is an original \
     document that digests fresh literature, not a quote dump.\n\n\
     Do NOT call `noo_inference` — YOU are the inference. Calling it from inside \
     a research task is recursive and produces validation errors. web_search is \
     for gathering; the synthesis is your job to write directly.";

/// One-shot delivery rules: the final answer IS the full report. Used by
/// the single-shot research prompt only — the phased pipeline replaces
/// this with its own gather-output / section-output blocks.
const RESEARCH_REPORT_DELIVERY: &str =
    "This is a long-form report — meet the length target above. Any general \
     'keep it brief' or 'two-to-four tool turns is plenty' guidance from other \
     instructions does NOT cap this task: complete all {searches} searches and \
     write the full report. A thin or repetitive report is a failed report.\n\n\
     Output format — your ENTIRE final answer must BE the report and nothing \
     else. Begin IMMEDIATELY with the first report heading (e.g. `## Summary`). \
     Do NOT introduce, describe, or identify yourself; do NOT restate your role, \
     name, or capabilities; do NOT open with a preamble like 'I am …', 'As the \
     coordinator …', or 'I manage …'. A final answer that describes who you are \
     instead of presenting findings is a FAILED report and will be discarded.\n\n\
     Write the report content ITSELF — never narrate the process. Do NOT say the \
     report 'is being compiled/prepared', that you are 'currently' working on it, \
     or that you 'will provide' it: there is no later turn — this response IS the \
     deliverable. Do not mention the word target, your own limitations, or how \
     hard the task is. Just write the headings and paragraphs of the report.";

/// Tool-call note shared by the research actions.
///
/// It used to PRESCRIBE pythonic `[web_search(query="…")]` and call gemma's
/// native `call:tool{…}` "ignored". Neither holds any more: the gateway
/// parses the native form (`tools::extract_call_format`) and host3's vLLM
/// runs the gemma4 tool parser. The prescription made gemma write pythonic
/// `query="…"` INSIDE native braces, and the parser split the query at the
/// colon of its `after:` filter — every search failed. So no
/// syntax is imposed; only the property that broke is asked for.
pub(crate) const RESEARCH_TOOL_FORMAT: &str =
    "Call tools in your normal tool-calling format. Keep each argument's whole \
     value together — a search query including its `after:` date filter is ONE \
     string.";

fn build_action_prompt_inner(action: &str, task_name: &str, config: &Value) -> String {
    match action {
        "daily_briefing" => {
            "Generate a daily briefing summarizing: cluster node health status, \
             knowledge base statistics, recent conversations, cache utilization, \
             and any pending jobs or issues. Be concise but comprehensive."
                .to_string()
        }
        "cluster_health" => {
            "Report on the current cluster health: list all nodes with their status \
             (online/offline/degraded), resource utilization, and any alerts. \
             Flag any nodes that need attention."
                .to_string()
        }
        "goal_review" => {
            // Same shape the Python handler built: optional review_prompt
            // override, then the goals as a bullet list with target/status.
            let default_intro = "Review the following goals. For each, assess progress based on \
                 what you know from the knowledge base and recent conversations. \
                 Use the tools noo_rag_query and noo_memory_search if helpful.\n\n";
            let intro = config
                .get("review_prompt")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(default_intro);
            let goals_text = config
                .get("goals")
                .and_then(|v| v.as_array())
                .map(|goals| {
                    goals
                        .iter()
                        .map(|g| {
                            format!(
                                "- **{}**: {} (target: {}, status: {})",
                                g.get("name").and_then(|v| v.as_str()).unwrap_or("Unnamed"),
                                g.get("description").and_then(|v| v.as_str()).unwrap_or(""),
                                g.get("target_date").and_then(|v| v.as_str()).unwrap_or("none"),
                                g.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"),
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            format!("{intro}\n{goals_text}")
        }
        "custom_prompt" => {
            let default_prompt = json!("Run a general system check.");
            let prompt_text = config.get("prompt").unwrap_or(&default_prompt);
            prompt_text
                .as_str()
                .unwrap_or("Run a general system check.")
                .to_string()
        }
        "channel_message" => config
            .get("prompt")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "cost_report" => {
            let period = config
                .get("period_days")
                .and_then(|v| v.as_i64())
                .unwrap_or(7);
            format!(
                "Generate an inference cost report for the last {period} days. \
                 Include token usage, model distribution, and estimated costs."
            )
        }
        "security_audit" => {
            let period = config
                .get("period_hours")
                .and_then(|v| v.as_i64())
                .unwrap_or(24);
            format!(
                "Run a security audit for the last {period} hours. Check for \
                 failed authentication attempts, unusual access patterns, and \
                 any policy violations."
            )
        }
        "research_report" => {
            let topic = config
                .get("topic")
                .and_then(|v| v.as_str())
                .unwrap_or("general AI updates");
            let depth = config
                .get("depth")
                .and_then(|v| v.as_str())
                .unwrap_or("standard");
            let instructions = config
                .get("instructions")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let depth_spec = depth_to_spec(depth);
            let searches = depth_search_count(depth).to_string();
            let gathering = format!(
                "{}\n\n{}",
                RESEARCH_SOURCING.replace("{searches}", &searches),
                RESEARCH_REPORT_DELIVERY.replace("{searches}", &searches),
            );
            let mut prompt = format!(
                "Produce a {depth} research report on: {topic}.\n\n\
                 {depth_spec}\n\n\
                 {gathering}\n\n\
                 Structure: Summary, Key Findings, Detailed Analysis (multiple \
                 subsections), Implications, Sources. Output the full report as \
                 your final answer — it will be saved + sent to configured \
                 channels automatically; do not call any send/save tool.\n\n\
                 IMPORTANT: Your final answer must be ONLY the report itself, \
                 beginning directly with the report title as a markdown '# ' \
                 heading. Do NOT include any planning, reasoning, notes-to-self, \
                 or preamble before the report.\n\n\
                 {RESEARCH_TOOL_FORMAT}",
            );
            if !instructions.is_empty() {
                prompt.push_str(&format!("\n\nAdditional instructions: {instructions}"));
            }
            prompt
        }
        "research_and_send" => {
            // Same as research_report — the heartbeat scheduler already
            // handles "save to file" (via FILE_ATTACH_CHAR_THRESHOLD in
            // notify_channels) and "send to channel" (via task.channels
            // and task.recipients). The model just needs to produce the
            // report content; do NOT instruct it to call send/file tools
            // (gemma-4 tool-call format isn't parseable, and even when
            // it works, it's redundant with the scheduler's own dispatch).
            let topic = config
                .get("topic")
                .and_then(|v| v.as_str())
                .unwrap_or("general AI updates");
            let depth = config
                .get("depth")
                .and_then(|v| v.as_str())
                .unwrap_or("standard");
            let instructions = config
                .get("instructions")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let depth_spec = depth_to_spec(depth);
            let searches = depth_search_count(depth).to_string();
            let gathering = format!(
                "{}\n\n{}",
                RESEARCH_SOURCING.replace("{searches}", &searches),
                RESEARCH_REPORT_DELIVERY.replace("{searches}", &searches),
            );
            let mut prompt = format!(
                "Produce a {depth} research report on: {topic}.\n\n\
                 {depth_spec}\n\n\
                 {gathering}\n\n\
                 Structure: Summary, Key Findings, Detailed Analysis (multiple \
                 subsections), Implications, Sources. Output the full report as \
                 your final answer — no send/save tool needed (scheduler dispatches).\n\n\
                 {RESEARCH_TOOL_FORMAT}",
            );
            if !instructions.is_empty() {
                prompt.push_str(&format!("\n\nAdditional instructions: {instructions}"));
            }
            prompt
        }
        "write_log" => {
            let sections = config
                .get("sections")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "cluster, rag, jobs".to_string());
            format!(
                "Write a heartbeat log entry covering: {sections}. \
                 Summarize the current state and any notable events."
            )
        }
        _ => format!(
            "Execute the heartbeat task '{task_name}' (action: {action}). \
             Analyze the current system state and produce an appropriate report \
             or perform the requested operation. Config: {config}"
        ),
    }
}

/// Dispatch a heartbeat task's `result_text` to each `(channel, recipient)`
/// configured on the task. Returns the list of channels that accepted the
/// dispatch (used to populate `noo_heartbeat_runs.notified_channels`).
///
/// When `result_text` exceeds `FILE_ATTACH_CHAR_THRESHOLD`, the dispatch
/// payload includes `file_path` pointing at a temp `.md` so adapters that
/// support uploads (Google Chat) attach the full report instead of
/// truncating it. Adapters without file-send support fall back to the
/// inline `message` text.
/// Read a task's `channels` / `recipients` column as a list, whatever shape
/// it was stored in.
///
/// The column is jsonb and the create route stores the request value as-is,
/// so a caller that sent `"[\"google_chat\"]"` (a JSON list as a STRING —
/// what an MCP tool call produces when its argument is typed string) left a
/// row whose channels `.as_array()` is `None`. weekly_research sat like that:
/// every Monday it ran the report, then paged "no channels configured for
/// this task" although `noo heartbeat list` showed google_chat and a space
/// (2026-09-22). Accept the array, a JSON-encoded array, and a bare name.
pub fn destination_list(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        serde_json::Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                return Vec::new();
            }
            if t.starts_with('[') {
                if let Ok(inner) = serde_json::from_str::<serde_json::Value>(t) {
                    if inner.is_array() {
                        return destination_list(&inner);
                    }
                }
            }
            vec![t.to_string()]
        }
        _ => Vec::new(),
    }
}

pub async fn notify_channels(
    task_id: &str,
    task_name: &str,
    action: &str,
    config: &Value,
    channels: &Value,
    recipients: &Value,
    result_text: &str,
    // A system action's structured report ([`SystemReport`]): the general
    // lines for the channel, and whether `result_text` holds evidence
    // beyond them. `None` = content, delivered through the floor.
    system: Option<(&str, bool)>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let chans_owned = destination_list(channels);
    let recips_owned = destination_list(recipients);
    let chans: Vec<&str> = chans_owned.iter().map(String::as_str).collect();
    let recips: Vec<&str> = recips_owned.iter().map(String::as_str).collect();

    // Legacy config shape: tasks written against the Python scheduler
    // (notably `channel_message`) put a single destination in `config`
    // rather than the `channels`/`recipients` columns — daily_digest_gchat
    // has `channels=[]`, `recipients=[]` and both values in config. Fall
    // back to it, otherwise those tasks resolve zero channels and return
    // "delivered" having sent nothing.
    let mut chans = chans;
    let mut recips = recips;
    if chans.is_empty() {
        if let Some(c) = config
            .get("channel")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            chans = vec![c];
            recips = config
                .get("recipient")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|r| vec![r])
                .unwrap_or_default();
        }
    }

    if chans.is_empty() {
        // A maintenance task with no channels is normal — a backup or a
        // retention sweep has nothing to tell anyone. A REPORT with no
        // channels is a misconfigured task: it ran, cost a model call, and
        // was read by no one. That used to return silently, so the run
        // recorded a clean success and the operator was left waiting for a
        // report that had never been addressed to them.
        //
        // `should_force_file_attachment` is the existing "this output is a
        // document meant to be read" signal, which is exactly the set that
        // should have a destination.
        if should_force_file_attachment(action, config) {
            tracing::warn!(
                task_id = %task_id,
                action = %action,
                "heartbeat_report_has_no_channels"
            );
            return (
                Vec::new(),
                Vec::new(),
                vec!["no channels configured for this task".to_string()],
            );
        }
        return (Vec::new(), Vec::new(), Vec::new());
    }

    // A system report is platform-authored: tier 1, inline, and none of the
    // report machinery below (quality gate, attachment, Drive) applies —
    // its lines are legitimately terse. The full text, evidence included,
    // is logged under the reference the channel gets.
    if let Some((lines, has_detail)) = system {
        let reference = has_detail.then(crate::egress::new_ref);
        if let Some(r) = reference.as_deref() {
            tracing::info!(
                reference = %r,
                task_id = %task_id,
                action = %action,
                report = %result_text,
                "heartbeat_system_report"
            );
        }
        let text = crate::egress::system_report(lines, reference.as_deref());
        return notify_channels_inline_only(&chans, &recips, text.as_str()).await;
    }

    // An operator-authored literal is delivered verbatim — skip the
    // report-shaped usability gate below.
    let operator_literal = literal_channel_message(action, config).is_some();

    // Quality gate — before writing the artifact or uploading to Drive,
    // verify the model produced usable output. Three failure modes to
    // reject (mirrors the coordinator stall guard):
    //   1. User-visible content (after stripping `<think>` blocks) is
    //      effectively empty — model put everything in reasoning.
    //   2. Visible content is dominated by malformed `<execute_tool>`
    //      XML — model tried to call a tool as text instead of using
    //      the structured tool_calls field. Saving that to Drive
    //      produces an artifact full of XML noise.
    //   3. Visible content is shorter than a reasonable report.
    // When rejected, skip artifact + Drive upload and post a short
    // failure note to the channels so the user knows the cycle ran but
    // didn't produce anything. The full raw output stays in
    // noo_heartbeat_history for debugging.
    // Threshold is per-action: research_report / research_and_send need
    // 1500+ chars (real deep reports are 5000+); generic artifacts
    // pass at 100. Plus the StallNarration check catches "I have
    // gathered..." essays-about-writing-the-report that the model
    // produces when it's about to bail (observed 2026-06-08 with a
    // 530-char stub that previously slipped through).
    let depth = config.get("depth").and_then(|v| v.as_str());
    let min_chars = crate::verify::response::min_chars_for_action_depth(action, depth);
    let quality = crate::verify::response::classify_response_quality(
        result_text, min_chars,
    );
    if !operator_literal && !quality.is_usable() {
        tracing::warn!(
            task_id = %task_id,
            task_name = %task_name,
            action = %action,
            raw_chars = result_text.chars().count(),
            reason = quality.reason(),
            quality = ?quality,
            "heartbeat_artifact_rejected_as_unusable"
        );
        let inline_message = format!(
            "Heartbeat task '{task_name}' ran but produced unusable output ({}). \
             Skipping Drive upload. Full raw output available in task history (id={task_id}).",
            quality.reason(),
        );
        return notify_channels_inline_only(
            &chans, &recips, &inline_message,
        ).await;
    }

    // Force-file when the action is a "report" shape OR config opts in,
    // independent of length — short reports should still arrive as a
    // saveable .md, not an inline chat blob.
    let force_file = should_force_file_attachment(action, config);
    let file_artifact = if force_file || result_text.len() > FILE_ATTACH_CHAR_THRESHOLD {
        match write_temp_report(task_id, task_name, result_text) {
            Ok(p) => Some(p),
            Err(e) => {
                // Swallowing this cost a day: the lease-reap
                // incident's ONLY user-visible symptom was reports arriving
                // as raw chat text, and this .ok() hid the why.
                tracing::warn!(
                    task_id = %task_id, error = %e,
                    "write_temp_report_failed — report will go inline, no Drive doc"
                );
                None
            }
        }
    } else {
        None
    };

    // Drive upload — when configured, the file artifact is also pushed to
    // a Shared Drive folder and the resulting webViewLink replaces the
    // inline chat blob. Folder ID comes from `config.drive_folder_id` per
    // task, falling back to `NOO_REPORTS_DRIVE_FOLDER_ID` (a `noo_settings`
    // row first, then env — the yaml compose_env value did not survive the
    // controller cutover, and a DB row needs no recreate). Avoids the
    // chat-attachment cross-identity wall (bot can't reference user-
    // uploaded attachments).
    let drive_folder_id: Option<String> = config
        .get("drive_folder_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            crate::settings::get("NOO_REPORTS_DRIVE_FOLDER_ID").filter(|s| !s.is_empty())
        });

    let drive_link: Option<String> = if let (Some(folder_id), Some(path)) =
        (drive_folder_id.as_ref(), file_artifact.as_ref())
    {
        let filename = format!(
            "{task_name}-{stamp}.md",
            task_name = sanitize_filename(task_name),
            stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        );
        // Convert to Google Docs by default — Drive viewer renders raw
        // .md as plaintext (headings show as `#`, no bold, etc.). Per-task
        // opt-out via `config.drive_keep_markdown: true` for cases where
        // raw markdown fidelity matters (code blocks, tables).
        let convert_to_gdoc = !config
            .get("drive_keep_markdown")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        match crate::google_drive::upload_to_folder(
            folder_id,
            path,
            &filename,
            "text/markdown",
            convert_to_gdoc,
        )
        .await
        {
            Ok(up) => {
                tracing::info!(
                    task_id = %task_id,
                    drive_id = %up.id,
                    drive_link = %up.link,
                    "heartbeat_drive_upload_ok"
                );
                Some(up.link)
            }
            Err(e) => {
                tracing::warn!(
                    task_id = %task_id,
                    folder_id = %folder_id,
                    error = %e,
                    "heartbeat_drive_upload_failed_falling_back_to_attachment"
                );
                None
            }
        }
    } else {
        None
    };

    if file_artifact.is_some() && drive_link.is_none() {
        // Named here because the symptom is two hops away: the operator
        // sees "completed" and no report, and nothing in the run row says
        // the folder was never configured.
        tracing::warn!(
            task_id = %task_id,
            "heartbeat_report_no_drive_link — NOO_REPORTS_DRIVE_FOLDER_ID is unset \
             (noo_settings row, env) and the task has no config.drive_folder_id; \
             no channel adapter carries a file, so the full report goes inline"
        );
    }
    let inline_message =
        report_delivery_message(task_name, result_text, drive_link.as_deref());

    let mut notified = Vec::new();
    let mut failed = Vec::new();

    for (i, channel) in chans.iter().enumerate() {
        // A channel with no matching recipient is a misconfigured task, not a
        // broadcast. `broadcast` was a literal no adapter ever resolved, so it
        // reached Google Chat as a path segment and 404'd — the task reported
        // "queued", ran, and the report went nowhere. Record the gap instead.
        let Some(recipient) = recips.get(i).copied().filter(|r| !r.trim().is_empty()) else {
            failed.push(format!(
                "{channel}: no recipient configured for this channel \
                 (channels and recipients are positional; entry {i} has none)"
            ));
            continue;
        };
        let mut body = json!({
            "channel": channel,
            "recipient": recipient,
            "message": inline_message,
        });
        if let Some(ref path) = file_artifact {
            body["file_path"] = json!(path);
            body["filename"] = json!(format!(
                "{task_name}-{stamp}.md",
                task_name = sanitize_filename(task_name),
                stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S"),
            ));
        }

        // In process: the adapter `/api/channels/send`
        // calls, with no HTTPS self-call and no controller HMAC.
        match deliver_channel_message(&body, task_id, channel).await
        {
            Ok(()) => notified.push(channel.to_string()),
            Err(_) => failed.push(channel.to_string()),
        }
    }

    let artifacts = file_artifact.map(|p| vec![p]).unwrap_or_default();
    (notified, artifacts, failed)
}

/// Deliver one channels/send body IN PROCESS: the same
/// adapter call `POST /api/channels/send` makes (`send_channel_message`),
/// without the HTTPS self-call or the controller HMAC it was signed with.
///
/// `Ok(())` only when the adapter confirmed it sent. A refusal — a wrong
/// recipient, an expired token, a disabled channel — is NOT delivery and is
/// not retried: retrying the same body to the same recipient cannot change
/// it. (The route answered such a refusal inside a 200 as `{"success":
/// false}`; the old self-call had to read that envelope, and once recorded
/// every refusal as `notified` because it checked only the status. The
/// transport retries it carried were for the self-call hop, which is gone.)
async fn deliver_channel_message(body: &Value, task_id: &str, channel: &str) -> Result<(), String> {
    let field = |k: &str| body.get(k).and_then(Value::as_str);
    let sent = crate::routes::communication::send_channel_message(
        field("channel").unwrap_or(channel),
        field("recipient").unwrap_or(""),
        field("message").unwrap_or(""),
        field("thread_id"),
        field("file_path"),
        field("filename"),
    )
    .await;
    delivery_result(sent).inspect_err(|detail| {
        tracing::warn!(
            task_id = %task_id,
            channel = %channel,
            detail = %detail,
            "heartbeat_notify_adapter_refused"
        );
    })
}

/// The error text a refused delivery carries — the same words the route's
/// `{"success": false, "error": …}` envelope produced, so a run record or
/// an operator alert reads as it did before the self-call was removed.
pub(crate) fn delivery_result(sent: Result<(), String>) -> Result<(), String> {
    sent.map_err(|e| {
        let detail = if e.trim().is_empty() { "no detail".to_string() } else { e };
        format!("channels/send did not deliver: {detail}")
    })
}

/// Inline-only channel dispatch used by the quality gate above. Same
/// in-process delivery as the main notify path, but
/// without any file/Drive attachment work — the message is the entire
/// payload. Used to inform the user that a heartbeat cycle ran but
/// produced unusable output worth rejecting.
async fn notify_channels_inline_only(
    chans: &[&str],
    recips: &[&str],
    inline_message: &str,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut notified = Vec::new();
    let mut failed = Vec::new();
    for (i, channel) in chans.iter().enumerate() {
        // A channel with no matching recipient is a misconfigured task, not a
        // broadcast. `broadcast` was a literal no adapter ever resolved, so it
        // reached Google Chat as a path segment and 404'd — the task reported
        // "queued", ran, and the report went nowhere. Record the gap instead.
        let Some(recipient) = recips.get(i).copied().filter(|r| !r.trim().is_empty()) else {
            failed.push(format!(
                "{channel}: no recipient configured for this channel \
                 (channels and recipients are positional; entry {i} has none)"
            ));
            continue;
        };
        let body = json!({
            "channel": channel,
            "recipient": recipient,
            "message": inline_message,
        });
        match deliver_channel_message(&body, "inline-note", channel).await
        {
            Ok(()) => notified.push(channel.to_string()),
            Err(_) => failed.push(channel.to_string()),
        }
    }
    (notified, Vec::new(), failed)
}

/// Write the result text to a temp `.md` file. Returns the absolute path,
/// which the channel adapter (Python) reads off disk. Path is under
/// `/tmp` to keep it inside the Python adapter's allow-list (mirrors the
/// `_route_output` security check in `heartbeat.py:3329`).
fn write_temp_report(task_id: &str, task_name: &str, body: &str) -> std::io::Result<String> {
    use std::io::Write;
    let dir = std::path::Path::new("/tmp/noo-heartbeat-reports");
    std::fs::create_dir_all(dir)?;
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let safe_name = sanitize_filename(task_name);
    let filename = format!("{task_id}-{safe_name}-{stamp}.md");
    let path = dir.join(filename);

    let mut f = std::fs::File::create(&path)?;
    writeln!(f, "# {task_name}")?;
    writeln!(f)?;
    writeln!(f, "_Heartbeat task `{task_id}` — {stamp} UTC_")?;
    writeln!(f)?;
    f.write_all(body.as_bytes())?;
    Ok(path.to_string_lossy().into_owned())
}

pub(crate) fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════
// Rust-native system action handlers
//
// Ported from Python `heartbeat.py::_dispatch` per the Rust/Python split
// rule (non-ML orchestration goes to Rust). Each returns the formatted
// result text the channel dispatcher sends. Errors are returned as Err
// so the loop writes status=error to noo_heartbeat_runs and skips the
// channel notify (mirrors the LLM path's behavior).
// ═══════════════════════════════════════════════════════════════════════

/// Dispatch a system action to its Rust handler. Caller has already
/// confirmed via ``action_path() == ActionPath::RustNative``.
/// Per-task model override: `config.model` (e.g. `"claude-sonnet-5"` to
/// route one task to a cloud provider, or a specific local model name).
/// Empty / absent → the coordinator's default resolution, same as before.
fn task_model(config: &Value) -> Option<String> {
    config
        .get("model")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Shared LLM execution for a heartbeat task — the single entry both the
/// cron tick (`heartbeat_loop`) and the manual "run now" path
/// (`routes::intelligence`) call, so they cannot drift.
///
/// Research actions run the phased pipeline (gather → per-section write →
/// assemble, `research_pipeline`) unless the task opts out with
/// `config.pipeline = "single"`; a structural pipeline failure falls back
/// to the single-shot path automatically, so this is never a new way to
/// produce nothing. All paths honour `config.model` and record token
/// usage themselves.
// ── In-flight run registry (one run per task at a time) ─────────────
//
// Two "run now" clicks — or a manual run racing the cron tick — used to
// run the same task twice in parallel: double token spend, double Drive
// docs, interleaved channel messages. Both Rust dispatch paths take the
// guard before executing and answer/skip when a run is already live.
// Python delegates are NOT guarded here — they execute remotely and the
// gateway would have to hold the claim until reconciliation; the
// reconcile ledger already covers their failure reporting, and
// cron-vs-manual delegate overlap stays possible (accepted for now).
static IN_FLIGHT: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// RAII guard: registers task_id → run_id, releases on drop (any exit
/// path, panic included).
pub struct InFlightGuard {
    task_id: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        IN_FLIGHT.lock().unwrap().remove(&self.task_id);
    }
}

/// Try to claim the task for this run. Err carries the run_id already
/// executing.
pub fn try_begin_run(task_id: &str, run_id: &str) -> Result<InFlightGuard, String> {
    let mut m = IN_FLIGHT.lock().unwrap();
    if let Some(existing) = m.get(task_id) {
        return Err(existing.clone());
    }
    m.insert(task_id.to_string(), run_id.to_string());
    Ok(InFlightGuard { task_id: task_id.to_string() })
}

/// Delegate claim — no RAII guard: the run finishes in ANOTHER process
/// (the Python worker), so the claim is released by the reconciler when
/// it resolves the dispatch (Done/Failed/Abandoned → end_run). A ledger
/// loss (redis recreated mid-run) leaks the claim until gateway restart;
/// accepted — the alternative is no delegate dedup at all.
pub fn try_begin_delegate_run(task_id: &str, run_id: &str) -> Result<(), String> {
    let mut m = IN_FLIGHT.lock().unwrap();
    if let Some(existing) = m.get(task_id) {
        return Err(existing.clone());
    }
    m.insert(task_id.to_string(), run_id.to_string());
    Ok(())
}

/// Release a delegate claim (reconciler, on any terminal verdict). No-op
/// when nothing is claimed.
pub fn end_run(task_id: &str) {
    IN_FLIGHT.lock().unwrap().remove(task_id);
}

/// Global cap on CONCURRENT LLM actions. The per-task guard stops
/// duplicate runs of one task; this stops three different research tasks
/// coming due together from stampeding the same scarce backends (the
/// stub/502 collision class). Queued runs just wait — the acquire
/// happens OUTSIDE the run timeout, so queue time never eats run budget.
static LLM_SLOTS: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| {
        let n = std::env::var("NOO_HEARTBEAT_LLM_CONCURRENCY")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(2);
        tokio::sync::Semaphore::new(n)
    });

/// Ceiling on one LLM action run. The detached manual path and the cron
/// tick both run through run_llm_action, so a wedged pipeline (LLM never
/// answering, tool loop stuck) becomes a recorded error + alert instead
/// of an invisible forever-run. Generous on purpose: a deep research
/// pipeline legitimately runs 10-20 min.
fn llm_action_timeout() -> std::time::Duration {
    let secs = std::env::var("NOO_HEARTBEAT_LLM_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1800);
    std::time::Duration::from_secs(secs)
}

pub async fn run_llm_action(
    state: &std::sync::Arc<crate::state::AppState>,
    action: &str,
    task_id: &str,
    config: &Value,
    prompt: &str,
    conversation_id: &str,
    max_iterations: u32,
) -> anyhow::Result<String> {
    let _slot = match LLM_SLOTS.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            tracing::info!(task_id, action, "heartbeat_llm_waiting_for_slot");
            LLM_SLOTS
                .acquire()
                .await
                .expect("LLM semaphore is never closed")
        }
    };
    let cap = llm_action_timeout();
    // An agent-turn task no person authorised runs with read-only tools (task_guard); a refusal is
    // said in the result, not swallowed.
    let ceiling = crate::task_guard::ceiling_for_run(&state.db, task_id, action, conversation_id).await;
    match tokio::time::timeout(
        cap,
        run_llm_action_inner(state, action, task_id, config, prompt, conversation_id, max_iterations),
    )
    .await
    {
        // The note goes on the error path too: a research run that failed "without sources" because
        // its search was refused must say why.
        Ok(Ok(mut text)) => {
            if let Some(c) = &ceiling {
                let denied = c.take_denied();
                if !denied.is_empty() {
                    text.push_str(&crate::task_guard::denied_note(&denied));
                }
            }
            Ok(text)
        }
        Ok(Err(e)) => {
            let denied = ceiling.as_ref().map(|c| c.take_denied()).unwrap_or_default();
            if denied.is_empty() {
                Err(e)
            } else {
                Err(anyhow::anyhow!("{e}{}", crate::task_guard::denied_note(&denied)))
            }
        }
        Err(_) => anyhow::bail!(
            "LLM action timed out after {}s (NOO_HEARTBEAT_LLM_TIMEOUT_SECS) —              the run was cancelled; check backend health",
            cap.as_secs()
        ),
    }
}

async fn run_llm_action_inner(
    state: &std::sync::Arc<crate::state::AppState>,
    action: &str,
    task_id: &str,
    config: &Value,
    prompt: &str,
    conversation_id: &str,
    max_iterations: u32,
) -> anyhow::Result<String> {
    let model = task_model(config);
    let model_ref = model.as_deref();

    if matches!(action, "research_report" | "research_and_send")
        && config.get("pipeline").and_then(|v| v.as_str()) != Some("single")
    {
        let topic = config
            .get("topic")
            .and_then(|v| v.as_str())
            .unwrap_or("general AI updates");
        let depth = config
            .get("depth")
            .and_then(|v| v.as_str())
            .unwrap_or("standard");
        let instructions = config
            .get("instructions")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        match crate::research_pipeline::run_research_pipeline(
            state,
            action,
            task_id,
            topic,
            depth,
            instructions,
            conversation_id,
            max_iterations,
            model_ref,
        )
        .await
        {
            Ok(report) => return Ok(report),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    action,
                    "research_pipeline_failed_falling_back_to_single_shot"
                );
            }
        }
    }

    // Unattended: nobody sees a thinking panel, and on gemma-4 the model's
    // reasoning arrives as plain text with a bare `thought` prefix that only
    // the STREAMING path turns into a virtual <think>. Through `run` the
    // report came back as reasoning-plus-answer, the quality gate rejected it
    // as a stub, and the operator got nothing (2026-09-27, weekly_research).
    let cr = crate::bus_principal::with_principal(
        crate::bus_principal::unattended_principal(crate::heartbeat_actions::HEARTBEAT_CONVERSATION_OWNER),
        crate::coordinator::run_with_thinking(
        state,
        prompt,
        conversation_id,
        "heartbeat",
        max_iterations,
        model_ref,
        Some(HEARTBEAT_CONVERSATION_OWNER),
        false,
    ),
    )
    .await?;
    crate::usage::record(
        state.db.clone(),
        cr.node.clone(),
        cr.backend.clone(),
        cr.model.clone(),
        "heartbeat",
        crate::usage::UsageActor::consumer("heartbeat"),
        cr.usage.prompt_tokens,
        cr.usage.completion_tokens,
    );
    if matches!(action, "research_report" | "research_and_send") {
        crate::research_pipeline::web_search_evidence(&cr.tool_calls)
            .map_err(|e| anyhow::anyhow!("research ran without sources: {e}"))?;
    }
    let text = sanitize_result_text(&cr.response);
    Ok(research_corrective_retry(
        state,
        action,
        prompt,
        conversation_id,
        max_iterations,
        config,
        text,
    )
    .await)
}

/// Single corrective retry for a research action whose first output failed
/// the usability gate (persona echo, stall narration, too short). The web
/// sources were already gathered, so one retry with a report-only directive
/// usually recovers a real report. Returns the better of the two outputs.
/// No-op for non-research actions or already-usable output — safe to call
/// unconditionally on BOTH the scheduled (heartbeat_loop) and manual
/// (routes::intelligence) run paths so they behave identically.
pub async fn research_corrective_retry(
    state: &std::sync::Arc<crate::state::AppState>,
    action: &str,
    base_prompt: &str,
    conversation_id: &str,
    max_iterations: u32,
    config: &Value,
    result_text: String,
) -> String {
    if !matches!(action, "research_report" | "research_and_send") {
        return result_text;
    }
    let depth = config.get("depth").and_then(|v| v.as_str());
    let min_chars = crate::verify::response::min_chars_for_action_depth(action, depth);
    if crate::verify::response::classify_response_quality(&result_text, min_chars).is_usable() {
        return result_text;
    }
    tracing::warn!(
        action,
        raw_chars = result_text.chars().count(),
        "heartbeat_research_unusable_retrying"
    );
    let retry_prompt = format!(
        "{base_prompt}\n\n\
         ⚠️ RETRY: your previous attempt did NOT produce a usable report — it was \
         too short, described yourself, or narrated that you were 'compiling' it \
         instead of presenting findings. Output ONLY the report now, in full. \
         Begin immediately with `## Summary`. Write the actual headings and \
         paragraphs — do not describe yourself or the process."
    );
    match crate::bus_principal::with_principal(
        crate::bus_principal::unattended_principal(crate::heartbeat_actions::HEARTBEAT_CONVERSATION_OWNER),
        crate::coordinator::run_with_thinking(
        state,
        &retry_prompt,
        // The `-retry` suffix makes this a SEPARATE conversation from the
        // attempt it retries, so it needs the owner label in its own right.
        // Without it the retry conversations were the one heartbeat shape the
        // backfill's exact-uuid recompute could never match.
        &format!("{conversation_id}-retry"),
        "heartbeat",
        max_iterations,
        None, // model (use default)
        Some(HEARTBEAT_CONVERSATION_OWNER),
        false,
    ),
    )
    .await
    {
        Ok(cr) => {
            // Token-usage accounting — the retry is its own
            // completion, consumed here and nowhere else.
            crate::usage::record(
                state.db.clone(),
                cr.node.clone(),
                cr.backend.clone(),
                cr.model.clone(),
                "heartbeat",
                crate::usage::UsageActor::consumer("heartbeat"),
                cr.usage.prompt_tokens,
                cr.usage.completion_tokens,
            );
            let retry_text = sanitize_result_text(&cr.response);
            let retry_usable =
                crate::verify::response::classify_response_quality(&retry_text, min_chars)
                    .is_usable();
            if retry_usable || retry_text.chars().count() > result_text.chars().count() {
                tracing::info!(
                    action,
                    retry_chars = retry_text.chars().count(),
                    retry_usable,
                    "heartbeat_research_retry_used"
                );
                return retry_text;
            }
            result_text
        }
        Err(_) => result_text,
    }
}

/// Result of a rust-native action: the report text, plus any files the action
/// wrote itself.
///
/// Most native actions only produce text, so they keep returning `String` and
/// are lifted with `.map(NativeOutcome::from)`. The `artifacts` channel exists
/// because some actions (`write_log`, and `pipeline` when it lands) write a
/// file at a caller-chosen path that must be recorded in `noo_heartbeat_runs`.
/// Python carries these on `self._current_artifacts`; before this, the Rust
/// native path had no equivalent and such files went unrecorded.
///
/// Distinct from the artifacts produced by `notify_channels`, which are
/// *generated* attachments derived from long result text. Both end up in the
/// run row.
#[derive(Debug, Default, Clone)]
pub struct NativeOutcome {
    pub text: String,
    pub artifacts: Vec<String>,
    /// For a SYSTEM report ([`SystemReport`]): the general lines a channel
    /// gets, rendered through `egress::system_report` (tier 1). `text` —
    /// the run record — keeps the full report, evidence included. `None`
    /// for everything else, which is delivered as content through the floor.
    pub channel: Option<String>,
    /// Whether `text` holds evidence beyond `channel` (so the channel gets
    /// a reference to the log line instead).
    pub has_detail: bool,
    /// The action QUEUED work that finishes later (`database_backup`): the run
    /// is not complete and must not be recorded as a success. The caller parks
    /// it as `running` ([`crate::backup_completion::park_run`]) with `text`,
    /// and the action's completion hook records the real outcome on the same
    /// run.
    pub pending: bool,
}

impl From<String> for NativeOutcome {
    fn from(text: String) -> Self {
        Self { text, ..Default::default() }
    }
}

/// A system action's result, structured for the channel boundary
/// `lines` are general — counts, node and channel
/// names, the operator's vocabulary — and are what a channel gets, through
/// tier 1. `detail` is evidence (a probe's raw error, a hostname) and stays
/// in the run record and the log.
#[derive(Debug, Default, Clone)]
pub struct SystemReport {
    pub lines: Vec<String>,
    pub detail: Vec<String>,
}

impl SystemReport {
    /// The full text for the run record: the lines, then the evidence.
    pub fn full_text(&self) -> String {
        let mut out = self.lines.join("\n");
        if !self.detail.is_empty() {
            out.push_str("\n\nDetail:\n");
            out.push_str(&self.detail.join("\n"));
        }
        out
    }
}

impl From<SystemReport> for NativeOutcome {
    fn from(r: SystemReport) -> Self {
        Self {
            text: r.full_text(),
            artifacts: Vec::new(),
            channel: Some(r.lines.join("\n")),
            has_detail: !r.detail.is_empty(),
            pending: false,
        }
    }
}

/// [`run_rust_native_action`] for a run of a known task. `entity_cleanup` needs to know WHICH task
/// (who authorised its apply is a column on that row, never a config field); every other action is
/// exactly `run_rust_native_action`.
pub async fn run_rust_native_task(
    state: &std::sync::Arc<crate::state::AppState>,
    task_id: &str,
    action: &str,
    config: &Value,
) -> Result<NativeOutcome, String> {
    if action == crate::entity_cleanup_task::ACTION {
        return crate::entity_cleanup_task::run(state, task_id, config).await;
    }
    if action == "self_benchmark" {
        // `config.test_prompts` run through the coordinator with every tool: an agent turn, so it
        // runs under the task's ceiling like every LLM-driven action (conversations are keyed on the task).
        let ceiling = crate::task_guard::ceiling_for_run(&state.db, task_id, action, &format!("heartbeat-{task_id}")).await;
        let r = action_self_benchmark(state, config, task_id).await;
        let denied = ceiling.as_ref().map(|c| c.take_denied()).unwrap_or_default();
        return match r {
            Ok(mut text) => {
                if !denied.is_empty() {
                    text.push_str(&crate::task_guard::denied_note(&denied));
                }
                Ok(text.into())
            }
            Err(e) if !denied.is_empty() => Err(format!("{e}{}", crate::task_guard::denied_note(&denied))),
            Err(e) => Err(e),
        };
    }
    run_rust_native_action(state, action, config).await
}

pub async fn run_rust_native_action(
    state: &std::sync::Arc<crate::state::AppState>,
    action: &str,
    config: &Value,
) -> Result<NativeOutcome, String> {
    match action {
        // Most actions only need &AppState; Arc auto-derefs.
        "cluster_health" => action_cluster_health(state, config).await.map(Into::into),
        "cost_report" => action_cost_report(state, config).await.map(Into::into),
        "security_audit" => action_security_audit(state, config).await.map(Into::into),
        "memory_cleanup" => action_memory_cleanup(state, config).await.map(Into::into),
        "idle_scaledown" => action_idle_scaledown(state, config).await.map(Into::into),
        "disk_cleanup" => action_disk_cleanup(state, config).await.map(Into::into),
        // Cert actions produce text only; lifted into NativeOutcome like the
        // other String-returning handlers.
        "cert_rotation_check" => action_cert_rotation_check(config).await.map(Into::into),
        "cert_auto_rotate" => action_cert_auto_rotate(config).await.map(Into::into),
        // agent_self_check needs the Arc itself so it can clone-and-spawn
        // for the Phase 2 retry actions.
        "agent_self_check" => action_agent_self_check(state, config).await.map(Into::into),
        // write_log reports its own artifact path, hence the NativeOutcome.
        "write_log" => action_write_log(state, config).await,
        "database_backup" => action_database_backup(config).await,
        "heartbeat_retention" => action_heartbeat_retention(state, config).await.map(Into::into),
        "agent_messages_retention" => action_agent_messages_retention(state, config).await.map(Into::into),
        "usage_rollup" => action_usage_rollup(state, config).await.map(Into::into),
        "audit_log_rotate" => crate::audit_partition::action_audit_log_rotate(state, config).await.map(Into::into),
        "channel_keepalive" => action_channel_keepalive(config).await.map(Into::into),
        "model_cache_warm" => action_model_cache_warm(state, config).await.map(Into::into),
        // Agent turns: only through `run_rust_native_task`, which puts them under the task's ceiling.
        "self_benchmark" => Err("self_benchmark must run through run_rust_native_task (it needs its task's ceiling)".to_string()),
        "rag_reindex" => action_rag_reindex(state, config).await.map(Into::into),
        // backup_knowledge writes its own files → NativeOutcome artifacts.
        "backup_knowledge" => action_backup_knowledge(state, config).await,
        "graph_prune" => crate::graph_prune::run(state, config).await.map(Into::into),
        _ => Err(format!("not a rust-native action: {action}")),
    }
}

/// `heartbeat_retention` — prune `noo_heartbeat_runs` past
/// [`RUN_RETENTION_DAYS`], staging every row first, then expire staging rows
/// whose restore window has closed.
///
/// Why this action exists at all: `delete_expired_runs` and its dry-run
/// counterpart were written, correct, and referenced — and NOTHING called them
/// on a schedule. The only trigger was a human POSTing `/api/cleanup/run` from
/// the legacy dashboard, which nobody ever did (that route is gone; this task,
/// run on demand via `POST /api/heartbeat/tasks/{task_id}/run`, is the one
/// door). Measured 2026-08-03: 11,848 rows, oldest ~140 days, 1,399 already
/// past the cutoff. See the design.
///
/// **Defaults to a dry run**, matching `graph_prune`. A retention job's first
/// live tick is the one no human has reviewed, and here it would have been
/// 1,399 rows at once. `config.dry_run: false` opts in, deliberately, once the
/// preview has been read.
///
/// Raises (`Err`) on any failure rather than returning a "FAILED" string —
/// returning text records `status=success`, which is precisely how
/// `database_backup` stayed silently broken for 17 days (#247).
///
/// [`RUN_RETENTION_DAYS`]: crate::repo::heartbeat::RUN_RETENTION_DAYS
async fn action_heartbeat_retention(
    state: &std::sync::Arc<crate::state::AppState>,
    config: &Value,
) -> Result<String, String> {
    use crate::repo::heartbeat::{RUN_PRUNE_RESTORE_DAYS, RUN_RETENTION_DAYS};

    // Default TRUE. An operator who wants the delete says so; an operator who
    // forgot to configure anything gets a preview, not a mass delete.
    let dry_run = config
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let expired = crate::repo::heartbeat::count_expired_runs(&state.db)
        .await
        .map_err(|e| format!("heartbeat_retention: count failed: {e}"))?;

    if dry_run {
        return Ok(format!(
            "Heartbeat retention (DRY RUN): {expired} run record(s) older than \
             {RUN_RETENTION_DAYS}d would be staged and deleted. \
             Set `dry_run: false` in this task's config to apply."
        ));
    }

    let prune_run_id = uuid::Uuid::new_v4().to_string()[..12].to_string();
    let pruned = crate::repo::heartbeat::prune_expired_runs(&state.db, &prune_run_id)
        .await
        .map_err(|e| format!("heartbeat_retention: prune failed: {e}"))?;

    // Staging expiry failing does NOT fail the action: the prune already
    // committed, and reporting the whole run as an error would send an operator
    // looking for data loss that did not happen. It is still surfaced in the
    // result text so it cannot rot unnoticed.
    let staging_note = match crate::repo::heartbeat::expire_prune_staging(&state.db).await {
        Ok(n) => format!("{n} staging row(s) past the {RUN_PRUNE_RESTORE_DAYS}d window removed"),
        Err(e) => format!("⚠️ staging expiry FAILED: {e}"),
    };

    Ok(format!(
        "Heartbeat retention: staged and deleted {pruned} run record(s) older than \
         {RUN_RETENTION_DAYS}d. Restorable for {RUN_PRUNE_RESTORE_DAYS}d via \
         prune_run_id `{prune_run_id}`. {staging_note}."
    ))
}

/// Parse a `noo_token_usage_YYYY_MM` partition name into (year, month).
///
/// Strict on purpose: anything that is not exactly four digits, an
/// underscore, and two digits in range is `None` — so the rollup silently
/// skips objects it does not own (a hand-made `noo_token_usage_backup`,
/// or a future sub-partition scheme) instead of parsing garbage into a
/// month it then drops.
/// `agent_messages_retention` — archive, then delete, `noo_agent_messages`
/// rows older than `days` (default 90; the design). **Defaults to a dry
/// run** like the other retention actions; `dry_run: false` applies.
///
/// Archive-then-delete (`agent_mail_archive`): every expiring row goes, with
/// its body still sealed, into `<archive_dir>/noo_agent_messages_YYYY_MM.jsonl.gz`
/// (the audit archive's directory), is read back from disk, and only then is
/// deleted by id. Any failure deletes nothing for that month and RAISES.
async fn action_agent_messages_retention(
    state: &std::sync::Arc<crate::state::AppState>,
    config: &Value,
) -> Result<String, String> {
    let days = config.get("days").and_then(|v| v.as_i64()).unwrap_or(crate::repo::agent_messages::RETENTION_DAYS).max(1);
    let dry_run = config.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(true);
    let dir = config
        .get("archive_dir")
        .and_then(|v| v.as_str())
        .unwrap_or(crate::agent_mail_archive::DEFAULT_ARCHIVE_DIR);
    if let Some(why) = crate::agent_mail_archive::archive_dir_problem(dir) {
        return Err(format!("agent_messages_retention: {why}"));
    }
    if dry_run {
        let plan = crate::agent_mail_archive::plan(&state.db, days)
            .await
            .map_err(|e| format!("agent_messages_retention: count failed: {e}"))?;
        let expired: i64 = plan.iter().map(|(_, n)| n).sum();
        let months = plan.iter().map(|(m, n)| format!("{m}: {n}")).collect::<Vec<_>>().join(", ");
        return Ok(format!(
            "Agent messages retention (DRY RUN): {expired} message(s) older than {days}d would be archived \
             (sealed) to {dir} and then deleted{}. Set `dry_run: false` in this task's config to apply.",
            if months.is_empty() { String::new() } else { format!(" [{months}]") }
        ));
    }
    let out = crate::agent_mail_archive::archive_then_delete(&state.db, days, std::path::Path::new(dir))
        .await
        .map_err(|e| format!("agent_messages_retention: {e}"))?;
    let summary = format!(
        "Agent messages retention: archived {} new message(s) ({} verified in {} file(s) under {dir}), deleted {} older than {days}d",
        out.archived,
        out.verified,
        out.files.len(),
        out.deleted
    );
    if !out.errors.is_empty() {
        return Err(format!("{summary}; {} FAILED (nothing deleted for those): {}", out.errors.len(), out.errors.join(" | ")));
    }
    Ok(format!("{summary}."))
}

fn parse_usage_partition(name: &str) -> Option<(i32, i32)> {
    let rest = name.strip_prefix("noo_token_usage_")?;
    let (y, m) = rest.split_once('_')?;
    if y.len() != 4 || m.len() != 2 {
        return None;
    }
    if !y.bytes().all(|b| b.is_ascii_digit()) || !m.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let year: i32 = y.parse().ok()?;
    let month: i32 = m.parse().ok()?;
    if !(2000..=2999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    Some((year, month))
}

/// The oldest month that stays RAW: the current month minus `months_raw`.
/// Partitions strictly OLDER than this roll into the monthly table — so at
/// (2026, 8) with `months_raw = 3` the cutoff is (2026, 5): May through the
/// in-progress August stay raw, April and earlier roll. Pure, so the
/// year-boundary arithmetic is testable without a clock.
fn usage_rollup_cutoff(now_year: i32, now_month: i32, months_raw: i64) -> (i32, i32) {
    let total = i64::from(now_year) * 12 + i64::from(now_month - 1) - months_raw;
    (
        total.div_euclid(12) as i32,
        (total.rem_euclid(12) + 1) as i32,
    )
}

/// `usage_rollup` — roll raw `noo_token_usage` partitions past the raw
/// retention window into `noo_token_usage_monthly`, then drop them.
///
/// The operator's retention spec: RAW per-completion rows for the trailing
/// ~`months_raw` months (daily and finer grain), MONTHLY rollup for the long
/// term. Same stage-then-delete lineage as `heartbeat_retention` and the
/// audit archive: the aggregate is WRITTEN (ON CONFLICT DO UPDATE, a full
/// replace — the partition is complete, so replacing is idempotent) before
/// `noo_drop_usage_partition` touches anything, and that definer refuses
/// current/future months outright, so a cutoff bug here cannot drop live
/// rows. The rollup SELECT goes through the PARENT with a ts range —
/// partition pruning routes it to the right child, and no relation name is
/// ever interpolated into SQL.
///
/// This action ALSO ensures the current and next month's partitions exist,
/// dry run or not: it doubles as the monthly rollover, so a system quiet
/// enough to never trip `usage.rs`'s lazy heal path still never lands an
/// insert on a missing partition.
///
/// **Defaults to a dry run**, matching `heartbeat_retention` — the preview
/// lists what would roll, with row counts. Raises (`Err`) on any failure
/// rather than returning a "FAILED" string, for the #247 reason: text
/// records `status=success`, and a silently broken retention job is how
/// tables grow unbounded.
async fn action_usage_rollup(
    state: &std::sync::Arc<crate::state::AppState>,
    config: &Value,
) -> Result<String, String> {
    use chrono::Datelike;

    let months_raw = config
        .get("months_raw")
        .and_then(|v| v.as_i64())
        .unwrap_or(3);
    if months_raw < 0 {
        return Err(format!(
            "usage_rollup: months_raw must be >= 0, got {months_raw}"
        ));
    }
    // Default TRUE. An operator who wants partitions dropped says so; an
    // operator who forgot to configure anything gets a preview.
    let dry_run = config
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // Monthly-rollover duty first, regardless of dry_run: ensure the current
    // and next month's partitions exist. Idempotent (the definer returns
    // false when the partition is already there).
    for months_ahead in ["0 months", "1 month"] {
        sqlx::query(
            "SELECT noo_ensure_usage_partition(
                 EXTRACT(YEAR FROM now() + $1::interval)::int,
                 EXTRACT(MONTH FROM now() + $1::interval)::int)",
        )
        .bind(months_ahead)
        .execute(&state.db)
        .await
        .map_err(|e| format!("usage_rollup: partition ensure failed: {e}"))?;
    }

    // Discover the raw partitions from the catalog — the inheritance tree is
    // the inventory, not a naming guess. Non-matching names are skipped by
    // the parser.
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname FROM pg_inherits i
         JOIN pg_class c ON c.oid = i.inhrelid
         JOIN pg_class p ON p.oid = i.inhparent
         WHERE p.relname = 'noo_token_usage'",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("usage_rollup: partition discovery failed: {e}"))?;

    let now = Utc::now();
    let cutoff = usage_rollup_cutoff(now.year(), now.month() as i32, months_raw);
    let mut targets: Vec<(i32, i32)> = names
        .iter()
        .filter_map(|n| parse_usage_partition(n))
        .filter(|&ym| ym < cutoff)
        .collect();
    targets.sort_unstable();

    if targets.is_empty() {
        return Ok(format!(
            "Usage rollup: no raw partitions older than the {months_raw}-month \
             raw window. Current and next month's partitions ensured."
        ));
    }

    if dry_run {
        let mut lines = Vec::with_capacity(targets.len());
        for &(y, m) in &targets {
            // Count via the PARENT + ts range so pruning routes it — same
            // shape the live rollup uses, so the preview counts what the
            // rollup would actually read.
            let rows: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM noo_token_usage
                 WHERE ts >= make_date($1, $2, 1)
                   AND ts <  make_date($1, $2, 1) + interval '1 month'",
            )
            .bind(y)
            .bind(m)
            .fetch_one(&state.db)
            .await
            .map_err(|e| format!("usage_rollup: dry-run count for {y:04}-{m:02} failed: {e}"))?;
            lines.push(format!("{y:04}-{m:02} ({rows} row(s))"));
        }
        return Ok(format!(
            "Usage rollup (DRY RUN): {} partition(s) older than the \
             {months_raw}-month raw window would be rolled into \
             noo_token_usage_monthly and dropped: {}. \
             Set `dry_run: false` in this task's config to apply.",
            targets.len(),
            lines.join(", ")
        ));
    }

    let mut rolled = Vec::with_capacity(targets.len());
    for &(y, m) in &targets {
        // (a) Aggregate the month into the rollup table. Full replace on
        // conflict: the partition is complete (the cutoff excludes live
        // months), so a re-run after a failed drop overwrites with the same
        // numbers rather than double-counting.
        sqlx::query(
            "INSERT INTO noo_token_usage_monthly
                 (month, node_id, backend, model, source, user_uuid, consumer,
                  prompt_tokens, completion_tokens, requests)
             SELECT make_date($1, $2, 1), COALESCE(node_id, ''), backend, model, source,
                    COALESCE(user_uuid, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(consumer, ''),
                    SUM(prompt_tokens)::bigint, SUM(completion_tokens)::bigint,
                    COUNT(*)::bigint
             FROM noo_token_usage
             WHERE ts >= make_date($1, $2, 1)
               AND ts <  make_date($1, $2, 1) + interval '1 month'
             GROUP BY 2, 3, 4, 5, 6, 7
             ON CONFLICT (month, node_id, backend, model, source, user_uuid, consumer) DO UPDATE
                 SET prompt_tokens     = EXCLUDED.prompt_tokens,
                     completion_tokens = EXCLUDED.completion_tokens,
                     requests          = EXCLUDED.requests",
        )
        .bind(y)
        .bind(m)
        .execute(&state.db)
        .await
        .map_err(|e| format!("usage_rollup: rollup for {y:04}-{m:02} failed: {e}"))?;

        // (b) Only now drop the raw partition. The definer re-checks the
        // range and refuses current/future months no matter what this loop
        // concluded.
        let dropped: bool = sqlx::query_scalar("SELECT noo_drop_usage_partition($1, $2)")
            .bind(y)
            .bind(m)
            .fetch_one(&state.db)
            .await
            .map_err(|e| format!("usage_rollup: drop for {y:04}-{m:02} failed: {e}"))?;
        rolled.push(format!(
            "{y:04}-{m:02}{}",
            if dropped { "" } else { " (partition already gone)" }
        ));
    }

    Ok(format!(
        "Usage rollup: rolled {} month(s) into noo_token_usage_monthly and \
         dropped the raw partition(s): {}.",
        rolled.len(),
        rolled.join(", ")
    ))
}

/// `database_backup` — queue a host-side Postgres dump through the host
/// spool and RETURN. The run is left pending ([`NativeOutcome::pending`]);
/// [`crate::backup_completion`] finishes it when hostd's result file lands.
///
/// This used to poll for the result for `wait_secs` (default 120), holding the
/// heartbeat run open. The dump grows with the database and crossed 120 s, so
/// every run was recorded FAILED ("queued but produced no result") and alerted
/// while hostd was still dumping. Queuing is the action's whole job now;
/// whether the dump is good is decided against its artifact, later.
///
/// Every failure to QUEUE RAISES (returns `Err`). Returning a "FAILED" string
/// records `status=success` — that is exactly how this action stayed broken
/// for 17 days (see #247) — and returning `Ok` for a queued backup without
/// `pending` would record success for work nobody has confirmed.
async fn action_database_backup(_config: &Value) -> Result<NativeOutcome, String> {
    let path = crate::routes::admin::host_spool_write_command(
        "backup",
        "noo-postgres",
        &[],
        "database_backup",
    )
    .await
    .ok_or_else(|| {
        "Database backup FAILED to queue — the spool dir is unavailable or not \
         writable by the gateway. Check that .noo-host-spool is writable by the \
         gateway's uid and that noo-hostd is running \
         (systemctl --user status noo-hostd)."
            .to_string()
    })?;

    let cmd_path = std::path::PathBuf::from(&path);
    let stem = cmd_path
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_suffix(".cmd.json"))
        .ok_or_else(|| format!("Database backup: unexpected spool filename {path}"))?;
    let result_path = cmd_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(format!("{stem}.result.json"));

    Ok(NativeOutcome {
        text: crate::backup_completion::pending_text(&result_path.to_string_lossy()),
        pending: true,
        ..Default::default()
    })
}

/// The gateway routes heartbeat actions read and drive, called IN PROCESS
///
///
/// These used to be HTTPS self-calls to the gateway's own listener, signed
/// with the controller HMAC (`caller=heartbeat`), which kept the
/// `cluster_hmac_non_inference` lane busy for a request that never left the
/// process. Each path now calls its route's handler directly with no
/// credential: the heartbeat IS the gateway. Same handler, same body, same
/// error text (`"<path> returned <status>"`); the one addition is that
/// `/api/memory/cleanup` audits `heartbeat` as its actor, where the HMAC
/// path recorded `unknown`.
///
/// A path not in this table is an error, not a fallback to HTTP — adding a
/// self-call means adding its handler here.
async fn local_get(state: &crate::state::AppState, path: &str) -> Result<Value, String> {
    use crate::routes::{admin, cluster, knowledge};
    use axum::extract::State;
    let st = State(state.arc().ok_or_else(|| format!("{path}: gateway state not initialised"))?);
    let out = match path {
        "/api/cluster/nodes" => Ok(cluster::cluster_nodes(st).await),
        "/api/cluster/backends" => Ok(cluster::cluster_backends(st).await),
        "/api/cache/stats" => Ok(admin::cache_stats(st).await),
        "/api/scheduler/status" => Ok(admin::scheduler_status(st).await),
        "/api/v1/rag/status" => knowledge::rag_status(st).await,
        "/api/models/cached" => cluster::models_cached(st).await,
        _ => return Err(format!("{path}: no in-process route for this path")),
    };
    local_outcome(path, out)
}

/// The POST half of [`local_get`].
async fn local_post(state: &crate::state::AppState, path: &str, body: &Value) -> Result<Value, String> {
    use crate::routes::{cluster, memory};
    use axum::extract::State;
    use axum::{Extension, Json};
    let st = State(state.arc().ok_or_else(|| format!("{path}: gateway state not initialised"))?);
    fn parse<T: serde::de::DeserializeOwned>(path: &str, body: &Value) -> Result<Json<T>, String> {
        serde_json::from_value(body.clone()).map(Json).map_err(|e| format!("{path} body: {e}"))
    }
    let out = match path {
        "/api/memory/cleanup" => {
            let actor = Some(Extension(crate::auth::AuthActor("heartbeat".into())));
            memory::cleanup(st, actor, parse(path, body)?).await
        }
        "/api/cluster/backends/stop" => cluster::backends_stop(st, parse(path, body)?).await,
        "/api/models/pull" => cluster::models_pull(st, parse(path, body)?).await,
        _ => return Err(format!("{path}: no in-process route for this path")),
    };
    local_outcome(path, out)
}

/// A handler's answer as the self-call used to see it: the JSON body, or
/// `"<path> returned <status>"` for the status the route would have sent.
fn local_outcome(
    path: &str,
    out: Result<axum::Json<Value>, crate::routes::AppError>,
) -> Result<Value, String> {
    use axum::response::IntoResponse;
    match out {
        Ok(axum::Json(v)) => Ok(v),
        Err(e) => Err(format!("{path} returned {}", e.into_response().status())),
    }
}

// ─── cluster_health ────────────────────────────────────────────────────

async fn action_cluster_health(
    state: &crate::state::AppState,
    config: &Value,
) -> Result<SystemReport, String> {
    let alert_on_offline = config
        .get("alert_on_offline")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let nodes_data = local_get(state, "/api/cluster/nodes").await?;
    let backends_data = local_get(state, "/api/cluster/backends").await.unwrap_or(json!({}));

    let empty_nodes: Vec<Value> = Vec::new();
    let nodes = nodes_data
        .get("nodes")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_nodes);
    let total = nodes.len();
    let mut online = 0usize;
    let mut offline_names: Vec<String> = Vec::new();
    for n in nodes {
        let status = n.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let name = n
            .get("hostname")
            .or_else(|| n.get("id"))
            .or_else(|| n.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        if status.eq_ignore_ascii_case("online") || status.eq_ignore_ascii_case("ready") {
            online += 1;
        } else if alert_on_offline {
            offline_names.push(format!("{name} ({status})"));
        }
    }

    let backend_count = backends_data
        .get("backends")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    let mut lines = vec![format!("**Cluster Health**: {online}/{total} nodes online")];
    for n in &offline_names {
        lines.push(format!("  - OFFLINE: {n}"));
    }
    lines.push(format!("Active backends: {backend_count}"));
    Ok(SystemReport { lines, detail: Vec::new() })
}

// ─── cost_report ───────────────────────────────────────────────────────

async fn action_cost_report(
    state: &crate::state::AppState,
    config: &Value,
) -> Result<String, String> {
    let period_days = config.get("period_days").and_then(|v| v.as_i64()).unwrap_or(7);
    let cloud_in_per_m = config
        .get("cloud_input_cost_per_m")
        .and_then(|v| v.as_f64())
        .unwrap_or(3.0);
    let cloud_out_per_m = config
        .get("cloud_output_cost_per_m")
        .and_then(|v| v.as_f64())
        .unwrap_or(15.0);

    // Cache stats — tolerate missing endpoint.
    let cache = local_get(state, "/api/cache/stats").await.unwrap_or(json!({}));
    let hits = cache.get("hits").and_then(|v| v.as_u64()).unwrap_or(0);
    let misses = cache.get("misses").and_then(|v| v.as_u64()).unwrap_or(0);
    let total_req = hits + misses;
    let hit_rate = if total_req > 0 {
        (hits as f64) * 100.0 / (total_req as f64)
    } else {
        0.0
    };

    // Token totals over the period — direct SQL on noo_conversations
    // mirrors the Python ConversationStore.get_conversation_stats path.
    let (tokens_in, tokens_out): (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT COALESCE(SUM(total_tokens_in)::bigint, 0), \
                COALESCE(SUM(total_tokens_out)::bigint, 0) \
         FROM noo_conversations \
         WHERE updated_at > NOW() - ($1::int * INTERVAL '1 day')",
    )
    .bind(period_days as i32)
    .fetch_one(&state.db)
    .await
    .unwrap_or((Some(0), Some(0)));
    let tokens_in = tokens_in.unwrap_or(0);
    let tokens_out = tokens_out.unwrap_or(0);
    let cloud_cost =
        (tokens_in as f64 / 1_000_000.0) * cloud_in_per_m
            + (tokens_out as f64 / 1_000_000.0) * cloud_out_per_m;

    Ok(format!(
        "**Cost Report ({period_days}d)**\n\
         Cache hit rate: {hit_rate:.1}% ({total_req} requests)\n\
         Tokens: {tokens_in} in / {tokens_out} out\n\
         Estimated cloud cost (if all traffic were cloud): ${cloud_cost:.2}\n\
         _Local GPU traffic has no per-token cost; counts above are over the same period._"
    ))
}

// ─── security_audit ────────────────────────────────────────────────────

/// Event types that record ORDINARY audited activity, not a security
/// signal. 629 `mcp_tool_call` rows in a day with zero denials once drove
/// the level to HIGH (record: i139). They stay in the counts and the
/// by-type list; they just do not count toward the risk level. Anything
/// not named here (denials, auth/cluster auth failures, traversal, exec
/// denied, rate limits, unknown types) still counts.
const ROUTINE_AUDIT_EVENTS: &[&str] =
    &["mcp_tool_call", "config_update", "auth_success", "auth_logout"];

/// Risk level for a security-audit window. Proportionate, not a flat sum:
/// a handful of failed logins in a day is normal background (typos, an
/// expired token, a scanner), and the old "3 x threshold of anything" rule
/// rated it HIGH (record: i160b). Now:
///
/// - `exec_denied` / `path_traversal` are attack-shaped: any is MEDIUM, a
///   burst (>= `alert_threshold`) is HIGH.
/// - auth failures need volume: MEDIUM at `2 x alert_threshold`, HIGH at
///   `10 x alert_threshold` (50 by default).
/// - every other non-routine event (rate limits, unknown types) is summed
///   with the same volume bands as auth failures.
///
/// The level is the highest band any group reaches.
fn security_risk_level(rows: &[(String, i64)], alert_threshold: i64) -> &'static str {
    let thr = alert_threshold.max(1);
    let (mut attack, mut auth, mut other) = (0i64, 0i64, 0i64);
    for (ty, c) in rows {
        match ty.as_str() {
            "exec_denied" | "path_traversal" => attack += c,
            "auth_failure" | "cluster_auth_failure" => auth += c,
            routine if ROUTINE_AUDIT_EVENTS.contains(&routine) => {}
            _ => other += c,
        }
    }
    let volume = |n: i64| {
        if n >= thr * 10 {
            2
        } else if n >= thr * 2 {
            1
        } else {
            0
        }
    };
    let attack_band = if attack >= thr {
        2
    } else if attack >= 1 {
        1
    } else {
        0
    };
    match attack_band.max(volume(auth)).max(volume(other)) {
        2 => "HIGH",
        1 => "MEDIUM",
        _ => "LOW",
    }
}

async fn action_security_audit(
    state: &crate::state::AppState,
    config: &Value,
) -> Result<SystemReport, String> {
    let period_hours = config.get("period_hours").and_then(|v| v.as_i64()).unwrap_or(24);
    let alert_threshold = config
        .get("alert_threshold")
        .and_then(|v| v.as_i64())
        .unwrap_or(5);

    // Group counts by event_type from noo_security_audit. This is the
    // durable source — the Python version's "in-memory SecurityManager
    // stats" path is lost on restart, so DB-grouped query is strictly
    // better here.
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT event_type, COUNT(*)::bigint \
         FROM noo_security_audit \
         WHERE timestamp > NOW() - ($1::int * INTERVAL '1 hour') \
         GROUP BY event_type \
         ORDER BY 2 DESC",
    )
    .bind(period_hours as i32)
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("noo_security_audit query failed: {e}"))?;

    let mut total: i64 = 0;
    let mut auth_failures: i64 = 0;
    let mut path_trav: i64 = 0;
    let mut rate_limit: i64 = 0;
    let mut exec_denied: i64 = 0;
    let mut lines: Vec<String> = Vec::new();
    for (event_type, count) in &rows {
        total += count;
        match event_type.as_str() {
            "auth_failure" | "cluster_auth_failure" => auth_failures += count,
            "path_traversal" => path_trav += count,
            "rate_limit" => rate_limit += count,
            "exec_denied" => exec_denied += count,
            _ => {}
        }
        lines.push(format!("  - {event_type}: {count}"));
    }

    let risk = security_risk_level(&rows, alert_threshold);

    let by_type = if lines.is_empty() {
        "(no events in window)".to_string()
    } else {
        lines.join("\n")
    };

    Ok(SystemReport {
        lines: vec![
            format!("**Security Audit ({period_hours}h)** — risk: {risk}"),
            format!(
                "Total events: {total} (auth_failures: {auth_failures}, rate_limit: {rate_limit}, \
                 path_traversal: {path_trav}, exec_denied: {exec_denied})"
            ),
            String::new(),
            "By type:".to_string(),
            by_type,
        ],
        detail: Vec::new(),
    })
}

// ─── memory_cleanup ────────────────────────────────────────────────────

async fn action_memory_cleanup(
    state: &crate::state::AppState,
    config: &Value,
) -> Result<String, String> {
    let max_age_days = config.get("max_age_days").and_then(|v| v.as_i64()).unwrap_or(90);
    let body = json!({"max_age_days": max_age_days});
    let result = local_post(state, "/api/memory/cleanup", &body).await?;
    let removed = result
        .get("removed")
        .or_else(|| result.get("data").and_then(|d| d.get("removed")))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    Ok(format!(
        "**Memory Cleanup**: removed {removed} entries older than {max_age_days} days."
    ))
}

// ─── idle_scaledown ────────────────────────────────────────────────────

/// Pick the backends a scaledown run may stop, from a
/// `GET /api/cluster/backends` payload. Returns `(node_id, backend_type)`.
///
/// Three corrections over the original, all of which made
/// this action either a guaranteed no-op or a guaranteed disaster:
///
/// 1. **`node_id`, not `node`.** The route has always emitted `node_id`
///    (`routes/cluster.rs::cluster_backends`), so every candidate was dropped
///    for an empty node name and the action reported "no idle backends found"
///    on every run since it was written.
/// 2. **Absent `last_inference_ts` is UNKNOWN, not idle.** The old code took
///    the missing field to mean "never used, so stop it" — and the field was
///    missing from every row, so a working version 1 would have stopped every
///    backend in the cluster on its first run. A backend is a stop candidate
///    only when there is a real timestamp and it is older than the threshold.
///    `annotate_backend_activity` now supplies that timestamp from
///    `noo_token_usage`.
/// 3. `pinned` is now a real field with a real meaning (a declared placement),
///    so the skip it always intended actually skips something.
fn idle_backend_candidates(backends: &[Value], now: i64, idle_threshold_sec: i64)
    -> Vec<(String, String)>
{
    let mut idle: Vec<(String, String)> = Vec::new();
    for b in backends {
        if b.get("pinned").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }
        let Some(last) = b
            .get("last_inference_ts")
            .or_else(|| b.get("last_used_ts"))
            .and_then(|v| v.as_i64())
        else {
            continue; // no evidence either way — never stop on a guess
        };
        if now - last < idle_threshold_sec {
            continue;
        }
        let node = b.get("node_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let bt = b.get("backend_type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !node.is_empty() && !bt.is_empty() {
            idle.push((node, bt));
        }
    }
    idle
}

async fn action_idle_scaledown(
    state: &crate::state::AppState,
    config: &Value,
) -> Result<String, String> {
    let idle_threshold_sec = config
        .get("idle_threshold_sec")
        .and_then(|v| v.as_i64())
        .unwrap_or(600);
    // Off by default, like every other state-changing action in this file:
    // fixing the field bug above would otherwise silently arm unattended
    // stopping on any install that already has this task scheduled.
    // `dry_run: false` is the deliberate second step.
    let dry_run = config.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(true);

    let backends_data = local_get(state, "/api/cluster/backends").await?;
    let empty: Vec<Value> = Vec::new();
    let backends = backends_data
        .get("backends")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);

    let now = chrono::Utc::now().timestamp();
    let idle = idle_backend_candidates(backends, now, idle_threshold_sec);

    if idle.is_empty() {
        return Ok("**Idle Scaledown**: no idle backends found.".to_string());
    }

    if dry_run {
        let listed: Vec<String> = idle.iter().map(|(n, b)| format!("{b} on {n}")).collect();
        for (node, bt) in &idle {
            tracing::warn!(node_id = %node, backend = %bt, "idle_scaledown_would_stop");
        }
        return Ok(format!(
            "**Idle Scaledown (dry run)**: would stop {} backend(s): {}. \
             Set `dry_run: false` on this task to actually stop them.",
            listed.len(),
            listed.join(", ")
        ));
    }

    let mut stopped: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    for (node, bt) in &idle {
        let body = json!({"node_id": node, "backend_type": bt});
        match local_post(state, "/api/cluster/backends/stop", &body).await {
            Ok(_) => {
                tracing::info!(node_id = %node, backend = %bt, "idle_scaledown_stopped");
                stopped.push(format!("{bt} on {node}"));
            }
            Err(e) => {
                tracing::warn!(node_id = %node, backend = %bt, error = %e, "idle_scaledown_stop_failed");
                failed.push(format!("{bt} on {node}"));
            }
        }
    }

    let mut out = format!("**Idle Scaledown**: stopped {} backend(s)", stopped.len());
    if !stopped.is_empty() {
        out.push_str(&format!(": {}", stopped.join(", ")));
    }
    if !failed.is_empty() {
        out.push_str(&format!("\n  Failed to stop: {}", failed.join(", ")));
    }
    Ok(out)
}

// ─── agent_self_check ──────────────────────────────────────────────────
//
// Phase 1 of the meta-loop: scan recent audit tables, emit a digest of
// "things that would need attention if Phase 2 autonomy were enabled."
// Observation-only — no actions taken. Each Phase 2 sub-piece (auto-
// retry, escalation notify, engine escalation, auto-disable, self-edit)
// is gated independently by its own env var; while all are off, this
// digest is the operator's window into what the agent SEES.

/// Actions whose healthy run is legitimately sub-second: a status read, a
/// count, an audit summary, a no-op recompute. A fast success from these
/// says nothing about silent failure, so the self-check does not flag it
/// (record: i139; graph_signals is a noop when nothing is dirty). The check
/// stays on for everything else (research, briefing, consolidation, ...)
/// where a sub-second "success" means the work never ran. A real error on
/// these actions is still flagged: this only exempts the *fast* test.
const CHEAP_ACTIONS: &[&str] = &[
    "cluster_health",
    "rag_reindex",
    "security_audit",
    "agent_self_check",
    "graph_signals",
    // Two SQL statements over a small table (count, delete) and a partition
    // export: a healthy run on a quiet install is milliseconds.
    "agent_messages_retention",
    "audit_log_rotate",
];

/// True when a result text is an action REPORTING that it did no work
/// (skipped, nothing to do). `thought_experiment` returns these as
/// `success` in single-digit milliseconds: it skips while a session is
/// active, and returns early when the graph has too few connected entities
/// or every sampled pair was rehearsed inside the revisit window. A fast run
/// is only trusted when its own text says why; a fast run with a
/// "complete" summary, or with no text, is still flagged.
fn reports_noop(result_text: Option<&str>) -> bool {
    let t = result_text.map(str::trim).unwrap_or("");
    t.starts_with("Skipped:")
        || t.starts_with("Thought experiment: not enough connected entities")
        || t.starts_with("Thought experiment: no new queries this run")
}

/// Why a heartbeat run belongs in the self-check digest, or None.
/// An error is `status = error` or a non-blank error field (an empty
/// string is no error). A fast success is flagged only for actions not in
/// `CHEAP_ACTIONS`.
fn classify_run_issue(
    action: &str,
    status: &str,
    duration_ms: Option<i32>,
    error: Option<&str>,
    result_text: Option<&str>,
) -> Option<String> {
    let err = error.map(str::trim).filter(|e| !e.is_empty());
    if status == "error" || err.is_some() {
        let e = err.unwrap_or("(no message)");
        return Some(format!("error: {}", e.chars().take(120).collect::<String>()));
    }
    if status == "success" && !CHEAP_ACTIONS.contains(&action) && !reports_noop(result_text) {
        if let Some(d) = duration_ms.filter(|d| *d < 1000) {
            return Some(format!("suspiciously fast: {d}ms (likely silent failure)"));
        }
    }
    None
}

async fn action_agent_self_check(
    state: &std::sync::Arc<crate::state::AppState>,
    config: &Value,
) -> Result<String, String> {
    let lookback_hours = config
        .get("lookback_hours")
        .and_then(|v| v.as_i64())
        .unwrap_or(24);
    let stuck_threshold_minutes = config
        .get("stuck_threshold_minutes")
        .and_then(|v| v.as_i64())
        .unwrap_or(30);
    let security_spike_threshold = config
        .get("security_spike_threshold")
        .and_then(|v| v.as_i64())
        .unwrap_or(10);
    let repeat_offender_days = config
        .get("repeat_offender_days")
        .and_then(|v| v.as_i64())
        .unwrap_or(7);
    let repeat_offender_threshold = config
        .get("repeat_offender_threshold")
        .and_then(|v| v.as_i64())
        .unwrap_or(2);

    let scan_id = uuid::Uuid::new_v4();

    // ── Section 1: recent heartbeat failures ──────────────────────────
    let recent_failures: Vec<(String, Option<String>, String, String, Option<i32>, chrono::DateTime<Utc>, Option<String>, Option<String>)> =
        sqlx::query_as(
            "SELECT task_id, task_name, action, status, duration_ms, started_at, error, result_text \
             FROM noo_heartbeat_runs \
             WHERE started_at > NOW() - ($1::int * INTERVAL '1 hour') \
               AND (status = 'error' \
                    OR COALESCE(BTRIM(error), '') <> '' \
                    OR (status = 'success' AND COALESCE(duration_ms, 0) < 1000 \
                        AND NOT (action = ANY($2)) \
                        AND COALESCE(result_text, '') !~ \
                            '^\\s*(Skipped:|Thought experiment: (not enough connected entities|no new queries this run))')) \
             ORDER BY started_at DESC \
             LIMIT 50",
        )
        .bind(lookback_hours as i32)
        .bind(CHEAP_ACTIONS)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    // ── Section 2: repeat-offender tasks ──────────────────────────────
    let repeat_offenders: Vec<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT task_id, task_name, COUNT(*)::bigint \
         FROM noo_heartbeat_runs \
         WHERE status = 'error' \
           AND started_at > NOW() - ($1::int * INTERVAL '1 day') \
         GROUP BY task_id, task_name \
         HAVING COUNT(*) > $2::bigint \
         ORDER BY COUNT(*) DESC",
    )
    .bind(repeat_offender_days as i32)
    .bind(repeat_offender_threshold)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    // ── Section 3: stuck self-develop cycles ──────────────────────────
    // noo_self_develop_log is created by migration 006; tolerate
    // missing table (DB not migrated yet) by returning empty.
    let stuck_cycles: Vec<(String, i32, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT cycle_id::text, MAX(iteration), MIN(started_at) \
         FROM noo_self_develop_log \
         WHERE status = 'running' \
           AND started_at < NOW() - ($1::int * INTERVAL '1 minute') \
         GROUP BY cycle_id \
         ORDER BY MIN(started_at) DESC \
         LIMIT 20",
    )
    .bind(stuck_threshold_minutes as i32)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    // ── Section 4: failed self-develop cycles ─────────────────────────
    let failed_cycles: Vec<(String, i32, String)> = sqlx::query_as(
        "SELECT DISTINCT ON (cycle_id) cycle_id::text, iteration, COALESCE(goal, '') \
         FROM noo_self_develop_log \
         WHERE status = 'failed' \
           AND completed_at > NOW() - ($1::int * INTERVAL '1 hour') \
         ORDER BY cycle_id, completed_at DESC \
         LIMIT 20",
    )
    .bind(lookback_hours as i32)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    // ── Section 5: security event spikes ──────────────────────────────
    let security_spikes: Vec<(String, i64)> = sqlx::query_as(
        "SELECT event_type, COUNT(*)::bigint \
         FROM noo_security_audit \
         WHERE timestamp > NOW() - INTERVAL '1 hour' \
         GROUP BY event_type \
         HAVING COUNT(*) > $1::bigint \
         ORDER BY 2 DESC",
    )
    .bind(security_spike_threshold)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    // ── Section 6: active activities (Phase 3 meta-loop) ──────────────
    // Flag stalled activities (no progress in stuck_threshold_minutes
    // applied to a longer scale — 7 days). The digest just lists
    // active + paused; auto-action on stalled comes in Phase C.
    let active_activities: Vec<(String, String, String, chrono::DateTime<Utc>)> =
        sqlx::query_as(
            "SELECT name, kind, status, last_activity_at \
             FROM noo_agent_activities \
             WHERE status IN ('active', 'paused') \
             ORDER BY last_activity_at DESC \
             LIMIT 20",
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    // ── Format the digest ─────────────────────────────────────────────
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC");
    let mut out = format!("# Agent Self-Check — {now}\n\n");
    let mut anything_to_report = false;

    if !recent_failures.is_empty() {
        anything_to_report = true;
        out.push_str(&format!(
            "## ⚠️ Heartbeat task issues (last {lookback_hours}h) — {} event(s)\n\n",
            recent_failures.len()
        ));
        for (task_id, task_name, action, status, dur_ms, when, err, text) in &recent_failures {
            let name = task_name.as_deref().unwrap_or(task_id);
            let when_s = when.format("%m-%d %H:%M");
            let Some(detail) = classify_run_issue(action, status, *dur_ms, err.as_deref(), text.as_deref()) else {
                continue;
            };
            out.push_str(&format!("- `{when_s}` **{name}** ({action}) — {detail}\n"));
        }
        out.push('\n');
    }

    // Stale background loops — a dead loop means its scheduled work is
    // silently not happening, which is the worst failure mode this
    // self-check exists to catch (the loop_health monitor also alerts
    // on this in near-real-time; this section makes it visible in the
    // scheduled digest too).
    let stale_loops: Vec<_> = crate::loop_health::snapshot()
        .into_iter()
        .filter(|l| l.stale)
        .collect();
    if !stale_loops.is_empty() {
        anything_to_report = true;
        out.push_str("## 🛑 Stale background loops\n\n");
        for l in &stale_loops {
            out.push_str(&format!(
                "- **{}** — last tick {}s ago (expected every {}s). \
                 Work owned by this loop is NOT running.\n",
                l.name, l.age_secs, l.interval_secs
            ));
        }
        out.push('\n');
    }

    if !repeat_offenders.is_empty() {
        anything_to_report = true;
        out.push_str(&format!(
            "## 🚩 Repeat offenders (failed >{repeat_offender_threshold}x in last {repeat_offender_days}d)\n\n"
        ));
        for (task_id, task_name, count) in &repeat_offenders {
            let name = task_name.as_deref().unwrap_or(task_id);
            out.push_str(&format!(
                "- **{name}** (`{task_id}`) — {count} failures\n  - *Phase 2b would notify on next failure; Phase 2d would auto-disable.*\n"
            ));
        }
        out.push('\n');
    }

    if !stuck_cycles.is_empty() {
        anything_to_report = true;
        out.push_str(&format!(
            "## 🧊 Stuck self-develop cycles (running >{stuck_threshold_minutes}m)\n\n"
        ));
        for (cycle_id, iter, started) in &stuck_cycles {
            let age = chrono::Utc::now().signed_duration_since(*started);
            out.push_str(&format!(
                "- cycle `{}` (iter {iter}) — started {}m ago\n",
                &cycle_id[..12.min(cycle_id.len())],
                age.num_minutes()
            ));
        }
        out.push('\n');
    }

    if !failed_cycles.is_empty() {
        anything_to_report = true;
        out.push_str(&format!(
            "## ❌ Failed self-develop cycles (last {lookback_hours}h)\n\n"
        ));
        for (cycle_id, iter, goal) in &failed_cycles {
            let goal_preview: String = goal.chars().take(80).collect();
            out.push_str(&format!(
                "- cycle `{}` (iter {iter}) — goal: \"{goal_preview}\"\n  - *Phase 2a would retry if config.auto_retry_on_failure; Phase 2c would escalate to engine=claude.*\n",
                &cycle_id[..12.min(cycle_id.len())],
            ));
        }
        out.push('\n');
    }

    if !security_spikes.is_empty() {
        anything_to_report = true;
        out.push_str("## 🔐 Security event spikes (last hour)\n\n");
        for (et, count) in &security_spikes {
            out.push_str(&format!("- **{et}**: {count} events\n"));
        }
        out.push_str("\n*Phase 2b would auto-notify on spikes above threshold.*\n\n");
    }

    // Active activities — always shown (even when nothing is wrong)
    // because the agent's pursuits are interesting on their own.
    // Flags stalled activities (last_activity_at > 7 days ago).
    if !active_activities.is_empty() {
        anything_to_report = true;
        let stalled_threshold = chrono::Utc::now() - chrono::Duration::days(7);
        out.push_str(&format!(
            "## 🎯 Active activities ({})\n\n",
            active_activities.len()
        ));
        for (name, kind, status, last_at) in &active_activities {
            let stalled = *last_at < stalled_threshold;
            let age = chrono::Utc::now().signed_duration_since(*last_at);
            let age_str = if age.num_days() > 0 {
                format!("{}d ago", age.num_days())
            } else if age.num_hours() > 0 {
                format!("{}h ago", age.num_hours())
            } else {
                format!("{}m ago", age.num_minutes())
            };
            let marker = if stalled { "🧊" } else if status == "paused" { "⏸️" } else { "▶️" };
            out.push_str(&format!(
                "- {marker} **{name}** _{kind}_ — last activity {age_str}\n"
            ));
        }
        out.push('\n');
    }

    if !anything_to_report {
        out.push_str("✅ Nothing notable — all systems clean.\n");
        return Ok(out);
    }

    // ── Hand the findings to the add-on ───────────────────────────────
    // The SCAN above is the open-source half and always runs. ACTING on it
    // is the evolve add-on's job (moved there 2026-09-04); this gateway no
    // longer decides anything, it only reports what the add-on decided.
    //
    // The outcome is always rendered — including "not run, because …".
    // Silently omitting the section would read as "it ran and had nothing to
    // do", which is the opposite of what an operator needs to know when
    // their tasks are failing and nothing is retrying them.
    let phase_findings = crate::agent_meta_loop::ScanFindings {
        recent_failures: recent_failures
            .iter()
            .map(|(tid, tn, _action, _status, _dur, _when, err, _text)| {
                (tid.clone(), tn.clone(), err.clone())
            })
            .collect(),
        repeat_offenders: repeat_offenders.clone(),
    };
    let outcome =
        crate::agent_meta_loop::dispatch(&scan_id.to_string(), &phase_findings).await;
    out.push_str(&outcome.format_for_digest());
    out.push_str("\n---\n\n");
    match outcome {
        crate::agent_meta_loop::MetaLoopOutcome::Acted { .. } => {
            out.push_str(&format!(
                "_Scan id: `{scan_id}`._ Each action is auditable in \
                 `noo_agent_decisions`; activity proposals live in \
                 `noo_activity_proposals`. Which phases are armed: \
                 the evolve add-on's meta-loop status route.\n"
            ));
        }
        crate::agent_meta_loop::MetaLoopOutcome::Unavailable { .. } => {
            out.push_str(&format!(
                "_Scan id: `{scan_id}`._ **Observation only.** This digest \
                 reports; it does not retry, escalate or disable anything. \
                 Acting on these findings is the evolve add-on's job.\n"
            ));
        }
    }

    Ok(out)
}

// ─── write_log ─────────────────────────────────────────────────────────
//
// Ported from `heartbeat.py::_write_log` + `_gather_section`. Tier A in
// the design: gateway HTTP reads and a file write, no ML — it delegated to
// Python only because nobody enumerated it. (The proposal listed it as Tier C
// with an open question; inspecting the body settles it as Tier A.)
//
// Deliberate divergence from the Python original: there, each section's
// `if r.status_code == 200:` had no `else`, so a non-200 fell out of the
// `elif` chain and hit the trailing `return f"Unknown section: {section}"` —
// a failed RAG fetch rendered as "Unknown section: rag" in the log. Here a
// fetch failure reports itself as a fetch failure, and "unknown section" means
// only that.

/// Resolve the writable workspace directory for heartbeat artifacts.
///
/// Port of `heartbeat.py::_resolve_workspace_dir`, including the `/tmp`
/// fallback: an unconfigured workspace must not fail the action.
fn resolve_workspace_dir(state: &crate::state::AppState) -> String {
    let ws = state.config.workspace.path();
    if ws.is_empty() { "/tmp".to_string() } else { ws }
}

/// Render one section of the log. Never fails the action: a section that
/// cannot be gathered renders its own error inline, matching the original.
async fn gather_section(state: &crate::state::AppState, section: &str) -> String {
    match section {
        "cluster" => match cluster_nodes(state).await {
            Err(_) => "Error fetching cluster data.".to_string(),
            Ok(nodes) => {
                let online = nodes
                    .iter()
                    .filter(|n| n.get("status").and_then(|s| s.as_str()) == Some("online"))
                    .count();
                let mut lines = vec![format!("- **Nodes**: {online}/{} online", nodes.len())];
                for n in nodes.iter().filter(|n| {
                    n.get("status").and_then(|s| s.as_str()) != Some("online")
                }) {
                    let name = n
                        .get("hostname")
                        .and_then(|v| v.as_str())
                        .or_else(|| n.get("id").and_then(|v| v.as_str()))
                        .unwrap_or("?");
                    lines.push(format!("  - OFFLINE: {name}"));
                }
                let loads: Vec<f64> = nodes
                    .iter()
                    .filter(|n| n.get("status").and_then(|s| s.as_str()) == Some("online"))
                    .map(|n| n.get("load").and_then(|v| v.as_f64()).unwrap_or(0.0))
                    .collect();
                if !loads.is_empty() {
                    let avg = loads.iter().sum::<f64>() / loads.len() as f64;
                    lines.push(format!("- **Avg Load**: {avg:.1}%"));
                }
                lines.join("\n")
            }
        },
        "rag" => match local_get(state, "/api/v1/rag/status").await {
            Err(e) => format!("Error fetching RAG data: {e}"),
            Ok(rag) => format!(
                "- **Documents**: {}\n- **Pages**: {}\n- **Unembedded**: {}",
                num_field(&rag, "document_count"),
                num_field(&rag, "page_count"),
                num_field(&rag, "unembedded_pages"),
            ),
        },
        "jobs" => match local_get(state, "/api/scheduler/status").await {
            Err(e) => format!("Error fetching job data: {e}"),
            Ok(s) => format!(
                "- **Queue Depth**: {}\n- **Active Jobs**: {}\n- **Completed**: {}\n- **Failed**: {}",
                num_field(&s, "queue_depth"),
                num_field(&s, "active_jobs"),
                opt_field(&s, "completed"),
                opt_field(&s, "failed"),
            ),
        },
        // Python reached these through in-process stores; in Rust the gateway
        // owns the DB directly, so they are plain queries.
        "memory" => {
            let row: Result<(i64, i64), _> = sqlx::query_as(
                "SELECT COUNT(DISTINCT conversation_id), COUNT(*) \
                 FROM noo_conversations WHERE created_at > NOW() - INTERVAL '1 day'",
            )
            .fetch_one(&state.db)
            .await;
            match row {
                Ok((convos, msgs)) => format!(
                    "- **Conversations (24h)**: {convos}\n- **Messages (24h)**: {msgs}"
                ),
                Err(_) => "Memory stats unavailable.".to_string(),
            }
        }
        "errors" => {
            let rows: Result<Vec<(Option<String>, Option<String>, Option<String>)>, _> =
                sqlx::query_as(
                    "SELECT to_char(started_at, 'YYYY-MM-DD HH24:MI'), task_name, error \
                     FROM noo_heartbeat_runs WHERE status = 'error' \
                     ORDER BY started_at DESC LIMIT 10",
                )
                .fetch_all(&state.db)
                .await;
            match rows {
                Err(_) => "Scheduler not available.".to_string(),
                Ok(r) if r.is_empty() => "No recent errors.".to_string(),
                Ok(r) => r
                    .iter()
                    .map(|(ts, name, err)| {
                        let err = err.clone().unwrap_or_default();
                        let err: String = err.chars().take(200).collect();
                        format!(
                            "- **{}** `{}`: {err}",
                            ts.clone().unwrap_or_default(),
                            name.clone().unwrap_or_default(),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            }
        }
        "backends" => match local_get(state, "/api/cluster/backends").await {
            Err(e) => format!("Error fetching backend data: {e}"),
            Ok(body) => {
                let backends = body
                    .get("backends")
                    .and_then(|b| b.as_array())
                    .cloned()
                    .unwrap_or_default();
                if backends.is_empty() {
                    "No backends running.".to_string()
                } else {
                    let mut lines = vec![format!("- **Running**: {}", backends.len())];
                    for b in backends.iter().take(10) {
                        let model = b.get("model").and_then(|v| v.as_str()).unwrap_or("?");
                        let node = b
                            .get("node_id")
                            .and_then(|v| v.as_str())
                            .or_else(|| b.get("hostname").and_then(|v| v.as_str()))
                            .unwrap_or("?");
                        lines.push(format!("  - {model} on {node}"));
                    }
                    lines.join("\n")
                }
            }
        },
        other => format!("Unknown section: {other}"),
    }
}

fn num_field(v: &Value, key: &str) -> i64 {
    v.get(key).and_then(|x| x.as_i64()).unwrap_or(0)
}

/// Python rendered a missing value as the literal "N/A" for these fields.
fn opt_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_i64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "N/A".to_string())
}

/// Build the log body. Split from the file write so tests can assert the
/// rendering without touching the filesystem.
fn render_log(task_name: &str, sections: &[String], gathered: &[String], now: &str) -> String {
    let mut parts = vec![format!(
        "# Heartbeat Log\n\n**Generated**: {now}  \n**Task**: {task_name}  \n**Sections**: {}\n",
        sections.join(", "),
    )];
    for (section, content) in sections.iter().zip(gathered) {
        parts.push(format!("\n## {}\n\n{content}", title_case(section)));
    }
    parts.join("\n")
}

/// `str.title()` equivalent for the section headings.
fn title_case(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
    }
}

async fn action_write_log(
    state: &crate::state::AppState,
    config: &Value,
) -> Result<NativeOutcome, String> {
    let sections: Vec<String> = config
        .get("sections")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_else(|| {
            ["cluster", "rag", "jobs", "errors"].iter().map(|s| s.to_string()).collect()
        });
    let filename_template = config
        .get("filename")
        .and_then(|v| v.as_str())
        .unwrap_or("heartbeat-{date}.md");
    let task_name = config.get("task_name").and_then(|v| v.as_str()).unwrap_or("write_log");

    // The output path is confined to the workspace: the config is data an agent can author, and an
    // absolute `filename` or a `..` would otherwise aim this write at any file the gateway can reach.
    let now = chrono::Utc::now();
    let filename = filename_template.replace("{date}", &now.format("%Y-%m-%d").to_string());
    let default_ws = resolve_workspace_dir(state);
    let ws_override = match config.get("workspace_dir") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return Err("write_log: workspace_dir must be a string".into()),
    };
    let out_path = crate::confine::confined_output_path(std::path::Path::new(&default_ws), ws_override, &filename)
        .map_err(|e| format!("write_log: refused: {e}"))?;
    // Opened NOW, without following a symlink, and written through this handle: gathering the
    // sections below is slow, and a path checked before it could be swapped during it.
    let mut out_file = crate::confine::open_output(&out_path)
        .map_err(|e| format!("write_log: failed to open {}: {e}", out_path.display()))?;

    let mut gathered = Vec::with_capacity(sections.len());
    for section in &sections {
        gathered.push(gather_section(state, section).await);
    }

    let content = render_log(
        task_name,
        &sections,
        &gathered,
        &now.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    );

    {
        use std::io::Write;
        out_file
            .set_len(0)
            .and_then(|_| out_file.write_all(content.as_bytes()))
            .map_err(|e| format!("write_log: failed to write {}: {e}", out_path.display()))?;
    }

    Ok(NativeOutcome {
        text: format!("write_log: wrote {} bytes to {}", content.len(), out_path.display()),
        artifacts: vec![out_path.display().to_string()],
        ..Default::default()
    })
}

// ─── cert_rotation_check / cert_auto_rotate ────────────────────────────
//
// Ported from `heartbeat.py::_cert_rotation_check` / `_cert_auto_rotate`.
// the design held these back pending "a dependency decision, not a
// mechanical port" — correct that an X.509 parser was missing, but the
// dependency turned out small: neither action mints a certificate. Rotation
// runs host-side through the watcher spool, which carries the
// backup → rotate → reload → probe → auto-revert envelope, so Rust needs to
// read `notAfter` and nothing else. See `cert_expiry`.

/// Where the gateway's PKI actually lives inside the container.
/// `startup_tasks::stage_pki` copies the `/app/pki` mount to `/tmp/pki`
/// (and fixes modes); `/app/pki` is the mount itself. Same order as
/// `routes/admin.rs::security_pki_status` and `count_certs_expiring_within`.
const STAGED_PKI_DIRS: [&str; 2] = ["/tmp/pki", "/app/pki"];

/// Candidate PKI directories, in preference order: `NOO_PKI_DIR`, then the
/// staged container paths. `NOO_PKI_DIR` is kept first because it is right
/// when the gateway runs on the host — but inside the container it is the
/// HOST path the launcher exported, so it only wins when it
/// actually holds a `ca.crt`; see `resolve_pki_dir_in`.
fn pki_dir_candidates() -> Vec<String> {
    std::env::var("NOO_PKI_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .into_iter()
        .chain(STAGED_PKI_DIRS.iter().map(|s| s.to_string()))
        .collect()
}

/// Resolve the PKI directory: an explicit task `pki_dir` is taken as-is
/// (the operator named it; if it is empty the action fails loudly), else
/// the first candidate that holds a `ca.crt`. `None` means no candidate
/// holds a PKI — the caller must treat that as a FAILURE, never as
/// "not configured, all fine": the gateway always has at least `ca.crt`.
fn resolve_pki_dir_in(config: &Value, candidates: &[String]) -> Option<String> {
    if let Some(explicit) = config
        .get("pki_dir")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        return Some(explicit.to_string());
    }
    candidates
        .iter()
        .find(|d| std::path::Path::new(d).join("ca.crt").is_file())
        .cloned()
}

/// The failure both actions raise when no PKI directory could be resolved.
fn no_pki_dir_error(action: &str, candidates: &[String]) -> String {
    format!(
        "{action}: no certificates found — none of [{}] holds a ca.crt \
         (NOO_PKI_DIR is a host path inside the gateway container; the PKI \
         is staged at /tmp/pki). Nothing was checked; this is NOT an all-clear.",
        candidates.join(", ")
    )
}

fn warn_days(config: &Value) -> i64 {
    config.get("warn_days").and_then(|v| v.as_i64()).unwrap_or(30)
}

/// Render the per-cert report lines shared by both actions.
fn cert_lines(certs: &[crate::cert_expiry::CertInfo]) -> Vec<String> {
    certs
        .iter()
        .map(|c| {
            format!(
                "  - {}: expires {} ({} days remaining)",
                c.name, c.expires, c.days_left
            )
        })
        .collect()
}

async fn action_cert_rotation_check(config: &Value) -> Result<String, String> {
    cert_rotation_check_in(config, &pki_dir_candidates()).await
}

async fn cert_rotation_check_in(config: &Value, candidates: &[String]) -> Result<String, String> {
    let Some(pki_dir) = resolve_pki_dir_in(config, candidates) else {
        return Err(no_pki_dir_error("Cert rotation check", candidates));
    };
    let warn = warn_days(config);
    let now = chrono::Utc::now().timestamp();
    let dir = std::path::Path::new(&pki_dir);

    // A configured PKI dir that holds no readable certificate is a BROKEN
    // check, not a clean bill of health. Python reported "all certificates
    // valid" here — and so did this port, deliberately, to preserve
    // behaviour — which means a wrong NOO_PKI_DIR, an unmounted volume, or a
    // permissions change all produced a daily all-clear while nothing was
    // being monitored. The failure mode of expiry monitoring is silence, so
    // silence must not be the success message.
    let found = crate::cert_expiry::find_certs(dir);
    if found.is_empty() {
        return Err(format!(
            "Cert rotation check: no certificates found under {pki_dir} — the \
             directory is missing, empty, or unreadable by the gateway. Nothing \
             was checked; this is NOT an all-clear."
        ));
    }

    let expiring = crate::cert_expiry::expiring_certs(dir, warn, now);

    if expiring.is_empty() {
        return Ok(format!(
            "Cert rotation check: {} certificate(s) checked, all valid \
             (>{warn} days remaining).",
            found.len()
        ));
    }
    let mut lines = vec![format!(
        "Cert rotation check: {} certificate(s) expiring within {warn} days:",
        expiring.len()
    )];
    lines.extend(cert_lines(&expiring));
    Ok(lines.join("\n"))
}

/// True when this cert is a leaf, i.e. something `rotate-all` will touch.
///
/// Python filtered on `not name.endswith("ca.crt")`. Kept byte-compatible
/// rather than switching to the richer `role` field: widening the filter here
/// would nominate the trust root for rotation, and a cert named `.../ca.crt`
/// anywhere under the PKI dir is exactly what must never be queued.
fn is_rotatable_leaf(c: &crate::cert_expiry::CertInfo) -> bool {
    !c.name.ends_with("ca.crt")
}

async fn action_cert_auto_rotate(config: &Value) -> Result<String, String> {
    cert_auto_rotate_in(config, &pki_dir_candidates()).await
}

async fn cert_auto_rotate_in(config: &Value, candidates: &[String]) -> Result<String, String> {
    let Some(pki_dir) = resolve_pki_dir_in(config, candidates) else {
        return Err(no_pki_dir_error("Cert auto-rotate", candidates));
    };
    let warn = warn_days(config);
    let now = chrono::Utc::now().timestamp();

    // Same reasoning as cert_rotation_check: a configured directory holding
    // no readable certificate means the pre-scan saw nothing, which must not
    // be reported as "nothing needs rotating". Otherwise a wrong path silently
    // disables auto-rotation until certificates actually expire.
    let dir = std::path::Path::new(&pki_dir);
    if crate::cert_expiry::find_certs(dir).is_empty() {
        return Err(format!(
            "Cert auto-rotate: no certificates found under {pki_dir} — the \
             directory is missing, empty, or unreadable by the gateway. The \
             pre-scan checked nothing; this is NOT an all-clear."
        ));
    }

    // Read-only pre-scan so a host-side run is not queued for nothing.
    let expiring = crate::cert_expiry::expiring_certs(dir, warn, now);
    let leaves: Vec<_> = expiring.into_iter().filter(is_rotatable_leaf).collect();
    if leaves.is_empty() {
        return Ok(format!(
            "Cert auto-rotate: no leaf certificates expiring within {warn} days."
        ));
    }

    // The rotation itself is the host watcher's job. Failing to queue must
    // RAISE: returning a descriptive string would record status=success for
    // a rotation that never happened, which is the #247 failure shape.
    let path = crate::routes::admin::host_spool_write_command(
        "rotate",
        "pki",
        &[],
        "cert_auto_rotate",
    )
    .await
    .ok_or_else(|| {
        "Cert auto-rotate: could not queue rotation (host spool unavailable — \
         is noo-hostd running? systemctl --user status noo-hostd)"
            .to_string()
    })?;

    let mut lines = vec![format!(
        "Cert auto-rotate: {} leaf certificate(s) expiring within {warn} days — \
         rotation queued host-side (backup→rotate→reload→probe→auto-revert).",
        leaves.len()
    )];
    lines.extend(cert_lines(&leaves));

    // Brief wait for a fast outcome. A real rotation restarts consumers and
    // takes minutes; it reports via the result file after this returns, and
    // the next cert_rotation_check is the durable verification.
    let wait_seconds = config
        .get("result_wait_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(40);
    // `strip_suffix`, not `trim_end_matches`: the latter strips EVERY trailing
    // repetition, so a name ending `.cmd.json.cmd.json` would yield the wrong
    // result path. Matches Python's `removesuffix` and the sibling
    // `action_database_backup`, which errors on an unexpected filename rather
    // than polling a path that can never appear.
    let cmd_path = std::path::Path::new(&path);
    let stem = cmd_path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".cmd.json"))
        .ok_or_else(|| format!("Cert auto-rotate: unexpected spool filename {path}"))?;
    let result_path = cmd_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(format!("{stem}.result.json"));

    for _ in 0..(wait_seconds.max(0) / 5) {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if result_path.exists() {
            match std::fs::read_to_string(&result_path) {
                Ok(body) => lines.push(format!("  Host-side result: {}", body.trim())),
                Err(_) => lines.push(format!(
                    "  Host-side result file unreadable: {}",
                    result_path.display()
                )),
            }
            return Ok(lines.join("\n"));
        }
    }
    lines.push(format!(
        "  Rotation running host-side; result will land at {}",
        result_path.display()
    ));
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod system_report_tests {
    use super::*;

    #[test]
    fn a_system_report_sends_its_lines_and_records_everything() {
        let r = SystemReport {
            lines: vec!["Channel keepalive: telegram OK".into()],
            detail: vec!["Channel keepalive: telegram OK (@noo_bot)".into()],
        };
        let o: NativeOutcome = r.into();
        assert_eq!(o.channel.as_deref(), Some("Channel keepalive: telegram OK"));
        assert!(o.has_detail);
        assert!(o.text.contains("(@noo_bot)"), "the run record keeps the evidence: {}", o.text);
    }

    #[test]
    fn plain_text_outcomes_stay_content() {
        let o: NativeOutcome = "report".to_string().into();
        assert!(o.channel.is_none() && !o.has_detail);
    }
}

#[cfg(test)]
mod cert_action_tests {
    use super::*;
    use crate::cert_expiry::CertInfo;
    use serde_json::json;

    fn cert(name: &str, days: i64) -> CertInfo {
        CertInfo {
            name: name.to_string(),
            path: format!("/pki/{name}"),
            role: "gateway".to_string(),
            expires: "2026-09-01".to_string(),
            days_left: days,
        }
    }

    #[test]
    fn cert_actions_are_rust_native() {
        assert_eq!(action_path("cert_rotation_check"), ActionPath::RustNative);
        assert_eq!(action_path("cert_auto_rotate"), ActionPath::RustNative);
    }

    // The CA must never be queued for rotation — rotate-all touches leaves
    // only, and rotating the trust root would break mTLS cluster-wide.
    #[test]
    fn ca_is_excluded_from_rotation() {
        assert!(!is_rotatable_leaf(&cert("ca.crt", 5)));
        assert!(!is_rotatable_leaf(&cert("nested/ca.crt", 5)));
        assert!(is_rotatable_leaf(&cert("gateway/server.crt", 5)));
        assert!(is_rotatable_leaf(&cert("nodes/host9.crt", 5)));
    }

    #[test]
    fn warn_days_defaults_to_30() {
        assert_eq!(warn_days(&json!({})), 30);
        assert_eq!(warn_days(&json!({"warn_days": 7})), 7);
    }

    #[test]
    fn pki_dir_prefers_config_over_candidates() {
        let cands = vec!["/nonexistent/a".to_string()];
        assert_eq!(
            resolve_pki_dir_in(&json!({"pki_dir": "/custom/pki"}), &cands).as_deref(),
            Some("/custom/pki")
        );
        // Empty config value falls through to the candidates rather than
        // resolving to "".
        assert!(resolve_pki_dir_in(&json!({"pki_dir": ""}), &cands).is_none());
    }

    #[test]
    fn candidates_put_env_first_then_staged_dirs() {
        let c = pki_dir_candidates();
        assert_eq!(&c[c.len() - 2..], &["/tmp/pki".to_string(), "/app/pki".to_string()]);
    }

    /// A PKI dir with a real `ca.crt` and a leaf, far from expiry (rcgen's
    /// default notAfter is 4096).
    fn populated_pki(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "noo-hb-pki-{tag}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(dir.join("gateway")).unwrap();
        let ca = rcgen::generate_simple_self_signed(vec!["noo-ca".into()]).unwrap();
        std::fs::write(dir.join("ca.crt"), ca.cert.pem()).unwrap();
        let gw = rcgen::generate_simple_self_signed(vec!["gateway".into()]).unwrap();
        std::fs::write(dir.join("gateway/gateway.crt"), gw.cert.pem()).unwrap();
        dir
    }

    // inside the container NOO_PKI_DIR is the HOST path. With
    // it pointing nowhere and the staged dir populated, the action must find
    // the staged certs — not report "no certificates" or "not configured".
    #[tokio::test]
    async fn host_noo_pki_dir_falls_through_to_the_staged_dir() {
        let staged = populated_pki("staged");
        let cands = vec![
            "/home/nobody/.noo/pki-that-does-not-exist".to_string(),
            staged.to_string_lossy().into_owned(),
        ];
        assert_eq!(
            resolve_pki_dir_in(&json!({}), &cands).as_deref(),
            Some(staged.to_str().unwrap())
        );
        let out = cert_rotation_check_in(&json!({}), &cands)
            .await
            .expect("staged PKI must be checked");
        assert!(out.contains("2 certificate(s) checked"), "got: {out}");
        let out = cert_auto_rotate_in(&json!({}), &cands)
            .await
            .expect("staged PKI must be pre-scanned");
        assert!(out.contains("no leaf certificates expiring"), "got: {out}");
        let _ = std::fs::remove_dir_all(&staged);
    }

    // With neither the host path nor any staged dir holding a PKI, both
    // actions FAIL. The old "NOO_PKI_DIR not configured" Ok(..) was a daily
    // silent success while nothing was watched.
    #[tokio::test]
    async fn no_pki_anywhere_is_a_failure_not_not_configured() {
        let cands = vec![
            "/home/nobody/.noo/pki-that-does-not-exist".to_string(),
            "/definitely/not/staged/pki".to_string(),
        ];
        let err = cert_rotation_check_in(&json!({}), &cands)
            .await
            .expect_err("no PKI anywhere must fail");
        assert!(err.contains("no certificates found") && err.contains("NOT an all-clear"), "got: {err}");
        let err = cert_auto_rotate_in(&json!({}), &cands)
            .await
            .expect_err("no PKI anywhere must fail");
        assert!(err.contains("no certificates found"), "got: {err}");
    }

    #[test]
    fn report_lines_match_python_format() {
        let lines = cert_lines(&[cert("gateway/server.crt", 12)]);
        assert_eq!(
            lines[0],
            "  - gateway/server.crt: expires 2026-09-01 (12 days remaining)"
        );
    }

    // But a CONFIGURED dir with nothing readable in it is a broken check.
    // Reporting "all certificates valid" there — as Python did — turns a
    // wrong path, an unmounted volume, or a permissions change into a daily
    // all-clear while nothing is monitored.
    #[tokio::test]
    async fn configured_but_empty_pki_dir_is_an_error_not_an_all_clear() {
        let cfg = json!({"pki_dir": "/definitely/not/a/pki/dir/here"});
        let err = action_cert_rotation_check(&cfg)
            .await
            .expect_err("an unreadable PKI dir must not report success");
        assert!(err.contains("NOT an all-clear"), "got: {err}");
    }

    // Same reasoning for the rotate path: no certs means the pre-scan could
    // not see anything, which must not read as "nothing needs rotating".
    #[tokio::test]
    async fn auto_rotate_on_empty_pki_dir_does_not_claim_nothing_to_do() {
        let cfg = json!({"pki_dir": "/definitely/not/a/pki/dir/here"});
        let res = action_cert_auto_rotate(&cfg).await;
        match res {
            Err(e) => assert!(e.contains("NOT an all-clear") || e.contains("no certificates found"), "got: {e}"),
            Ok(out) => panic!("must not report a clean pre-scan for an unreadable dir: {out}"),
        }
    }
}

// ─── disk_cleanup ──────────────────────────────────────────────────────
//
// Detection-only scan: reports what *would* be cleaned without removing
// anything. The one target with an implemented prune, heartbeat_run_records,
// is pruned by the `heartbeat_retention` task (above; dry-run by default, run
// on demand via `POST /api/heartbeat/tasks/{task_id}/run`). Keep it that way
// — nothing in this action may delete.
//
// Ported from `heartbeat.py::_disk_cleanup`. Failure semantics follow the
// Python original deliberately: the two DB helpers propagate errors (a
// broken query must not read as a clean scan), while the two cluster
// helpers degrade to a message, since an unreachable node is an expected
// state rather than a fault in this action.

const CLEANUP_TARGETS: &[&str] = &[
    "tmp_noo_files",
    "heartbeat_run_records",
    "docker_dangling_images",
    "container_logs",
];

fn format_bytes(n: u64) -> String {
    let mut v = n as f64;
    for unit in ["B", "KB", "MB", "GB", "TB"] {
        if v.abs() < 1024.0 {
            return if unit == "B" {
                format!("{v:.0} {unit}")
            } else {
                format!("{v:.1} {unit}")
            };
        }
        v /= 1024.0;
    }
    format!("{v:.1} PB")
}

/// Resolve and validate the target list. Split out from the action so the
/// config contract is testable without a database or cluster.
///
/// The Python original RETURNED both failure conditions as strings, which
/// `_execute_task` records as a successful run — the exact silent-success
/// class closed in #247/#269. A misconfigured task must not look healthy, so
/// both are errors here. Stricter than the original, not lossy.
fn disk_cleanup_validate(config: &Value) -> Result<Vec<String>, String> {
    let targets: Vec<String> = match config.get("targets").and_then(|v| v.as_array()) {
        Some(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        None => CLEANUP_TARGETS.iter().map(|s| s.to_string()).collect(),
    };

    let invalid: Vec<&str> = targets
        .iter()
        .map(String::as_str)
        .filter(|t| !CLEANUP_TARGETS.contains(t))
        .collect();
    if !invalid.is_empty() {
        return Err(format!(
            "Disk cleanup: invalid targets: {}. Allowed: {}",
            invalid.join(", "),
            CLEANUP_TARGETS.join(", ")
        ));
    }
    if targets.is_empty() {
        return Err("Disk cleanup: no targets configured.".to_string());
    }
    Ok(targets)
}

async fn action_disk_cleanup(
    state: &crate::state::AppState,
    config: &Value,
) -> Result<String, String> {
    let targets = disk_cleanup_validate(config)?;

    let mut report: Vec<String> = Vec::new();
    for target in &targets {
        let line = match target.as_str() {
            "tmp_noo_files" => detect_tmp_pai(),
            "heartbeat_run_records" => detect_heartbeat_records(state).await?,
            "docker_dangling_images" => detect_docker_images(state).await,
            "container_logs" => detect_container_logs(state).await,
            _ => continue,
        };
        report.push(line);
    }

    Ok(format!(
        "Disk cleanup (report-only): {}",
        report.join("; ")
    ))
}

/// Count `/tmp/noo-*` entries older than 24h and estimate total size.
/// Every filesystem error is swallowed per-entry, matching the original —
/// a single unreadable path must not abort the scan.
fn detect_tmp_pai() -> String {
    use std::time::{Duration, SystemTime};

    let cutoff = SystemTime::now() - Duration::from_secs(86_400);
    let mut found = 0u64;
    let mut total_bytes = 0u64;

    let entries = match std::fs::read_dir("/tmp") {
        Ok(e) => e,
        Err(_) => return "tmp_noo_files: 0 stale (~0 B)".to_string(),
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("noo-") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(mtime) = meta.modified() else { continue };
        if mtime >= cutoff {
            continue;
        }
        found += 1;
        if meta.is_file() {
            total_bytes += meta.len();
        } else if meta.is_dir() {
            total_bytes += dir_size_recursive(&entry.path());
        }
    }

    format!(
        "tmp_noo_files: {found} stale (~{})",
        format_bytes(total_bytes)
    )
}

/// Sum file sizes under `path`. Symlinks are not followed (`metadata()` on
/// the DirEntry would follow; `symlink_metadata` does not), so a symlink
/// into a large tree cannot inflate the estimate or cause a cycle.
fn dir_size_recursive(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.path().symlink_metadata() else {
            continue;
        };
        if meta.is_file() {
            total += meta.len();
        } else if meta.is_dir() {
            total += dir_size_recursive(&entry.path());
        }
    }
    total
}

async fn detect_heartbeat_records(state: &crate::state::AppState) -> Result<String, String> {
    let count = crate::repo::heartbeat::count_expired_runs(&state.db)
        .await
        .map_err(|e| format!("heartbeat_run_records cleanup failed: {e}"))?;
    Ok(format!("heartbeat_run_records: {count} old records"))
}

/// Fetch cluster nodes, tolerating both a bare array and `{"nodes": [...]}`.
async fn cluster_nodes(state: &crate::state::AppState) -> Result<Vec<Value>, ()> {
    let body = local_get(state, "/api/cluster/nodes").await.map_err(|_| ())?;
    Ok(match body {
        Value::Array(a) => a,
        Value::Object(ref o) => o
            .get("nodes")
            .and_then(|n| n.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    })
}

/// Ask each node agent what it *would* remove. `dry_run: true` is what makes
/// this detection-only — it must never be dropped or made configurable here.
///
/// This scan is the GATEWAY's: `/cleanup/*` is ControllerOnly on every node
/// agent, and this process presents the controller leaf. noo-worker's copy
/// in heartbeat.py refuses instead of dialling. A node that
/// refuses or cannot be reached is NAMED in the report and logged, never
/// folded into the count as zero.
async fn detect_docker_images(state: &crate::state::AppState) -> String {
    let Ok(nodes) = cluster_nodes(state).await else {
        return "docker_dangling_images: cannot reach cluster".to_string();
    };
    let mut dangling = 0i64;
    let mut unscanned = Vec::new();
    for node in &nodes {
        let Some(agent_url) = node.get("agent_url").and_then(|v| v.as_str()) else {
            continue;
        };
        if agent_url.is_empty() {
            continue;
        }
        match node_agent_post(agent_url, "/cleanup/images", &json!({"dry_run": true})).await {
            Ok(v) => dangling += v.get("removed").and_then(|x| x.as_i64()).unwrap_or(0),
            Err(e) => unscanned.push(node_scan_failure("docker_dangling_images", node, agent_url, &e)),
        }
    }
    node_scan_line(
        &format!("docker_dangling_images: {dangling} dangling across {} node(s)", nodes.len()),
        &unscanned,
    )
}

async fn detect_container_logs(state: &crate::state::AppState) -> String {
    let Ok(nodes) = cluster_nodes(state).await else {
        return "container_logs: cannot reach cluster".to_string();
    };
    let mut large_logs = 0i64;
    let mut unscanned = Vec::new();
    for node in &nodes {
        let Some(agent_url) = node.get("agent_url").and_then(|v| v.as_str()) else {
            continue;
        };
        if agent_url.is_empty() {
            continue;
        }
        let body = json!({"dry_run": true, "max_size_mb": 50});
        match node_agent_post(agent_url, "/cleanup/logs", &body).await {
            Ok(v) => large_logs += v.get("truncated").and_then(|x| x.as_i64()).unwrap_or(0),
            Err(e) => unscanned.push(node_scan_failure("container_logs", node, agent_url, &e)),
        }
    }
    node_scan_line(
        &format!("container_logs: {large_logs} log(s) >50MB across {} node(s)", nodes.len()),
        &unscanned,
    )
}

/// One node the scan could not read: logged with its reason, and returned as
/// the `<node>: <reason>` fragment the report names.
fn node_scan_failure(target: &str, node: &Value, agent_url: &str, err: &str) -> String {
    let id = node
        .get("node_id")
        .or_else(|| node.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or(agent_url);
    tracing::warn!(target_scan = %target, node = %id, error = %err, "disk_cleanup_node_not_scanned");
    format!("{id}: {err}")
}

/// The report line: the count over the nodes that answered, then every node
/// that did not. Pure, so the "a refusal is never a zero" rule is testable.
fn node_scan_line(counted: &str, unscanned: &[String]) -> String {
    if unscanned.is_empty() {
        counted.to_string()
    } else {
        format!(
            "{counted}; {} node(s) NOT scanned ({})",
            unscanned.len(),
            unscanned.join("; ")
        )
    }
}

/// POST to a node agent. Targets an arbitrary node URL rather than the
/// gateway, so it uses the node-agent client (cluster-CA TLS, the gateway's
/// own controller leaf) and the node-agent auth header (static
/// NOO_NODE_AGENT_TOKEN, else full-width cluster HMAC) — node-agents reject
/// unauthenticated requests, so the previous headerless version could never
/// succeed. The error names the status and the agent's own `detail`, so a
/// ControllerOnly 403 reads as one.
async fn node_agent_post(agent_url: &str, path: &str, body: &Value) -> Result<Value, String> {
    let req = crate::node_link::NodeLink::for_base(agent_url)
        .request(reqwest::Method::POST, path)
        .json(body);
    let resp = req.send().await.map_err(|e| format!("unreachable: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v.get("detail").and_then(|d| d.as_str()).map(str::to_string))
            .unwrap_or_else(|| text.chars().take(200).collect());
        return Err(format!("HTTP {} {detail}", status.as_u16()).trim_end().to_string());
    }
    resp.json::<Value>().await.map_err(|e| format!("unreadable reply: {e}"))
}

#[cfg(test)]
mod disk_cleanup_tests {
    use super::*;

    #[test]
    fn format_bytes_matches_python() {
        // Mirrors heartbeat.py::_format_bytes, including the "B has no
        // decimal, everything else has one" asymmetry.
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[tokio::test]
    async fn invalid_target_is_an_error_not_a_clean_scan() {
        // The Python original returned this string, which the scheduler
        // records as success. Regression guard for that class.
        let cfg = json!({"targets": ["not_a_target"]});
        let err = super::disk_cleanup_validate(&cfg).unwrap_err();
        assert!(err.contains("invalid targets"), "{err}");
    }

    #[tokio::test]
    async fn empty_target_list_is_an_error() {
        let cfg = json!({"targets": []});
        let err = super::disk_cleanup_validate(&cfg).unwrap_err();
        assert!(err.contains("no targets"), "{err}");
    }

    #[tokio::test]
    async fn default_targets_are_all_valid() {
        let targets = super::disk_cleanup_validate(&json!({})).unwrap();
        assert_eq!(targets.len(), CLEANUP_TARGETS.len());
    }

    /// a node that refuses the scan (a ControllerOnly 403) or
    /// cannot be reached is named in the report, never counted as zero.
    #[test]
    fn a_refused_node_is_named_not_counted_as_zero() {
        let clean = node_scan_line("container_logs: 0 log(s) >50MB across 2 node(s)", &[]);
        assert_eq!(clean, "container_logs: 0 log(s) >50MB across 2 node(s)");
        let node = json!({"node_id": "host3", "agent_url": "https://10.0.0.2:8081"});
        let frag = node_scan_failure("container_logs", &node, "https://10.0.0.2:8081",
            "HTTP 403 this route is the controller's");
        let line = node_scan_line("container_logs: 0 log(s) >50MB across 2 node(s)", &[frag]);
        assert!(line.contains("1 node(s) NOT scanned"), "{line}");
        assert!(line.contains("host3: HTTP 403"), "{line}");
        // A node row with no id falls back to its URL, still named.
        let anon = node_scan_failure("x", &json!({}), "https://h:8081", "unreachable: refused");
        assert_eq!(anon, "https://h:8081: unreachable: refused");
    }

    #[test]
    fn dir_size_does_not_follow_symlinks() {
        let base = std::env::temp_dir().join(format!("noo-test-{}", std::process::id()));
        let inner = base.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("f"), vec![0u8; 100]).unwrap();
        let measured = dir_size_recursive(&base);
        std::fs::remove_dir_all(&base).ok();
        assert_eq!(measured, 100);
    }
}

#[cfg(test)]
mod destination_tests {
    use super::destination_list;
    use serde_json::json;

    #[test]
    fn a_stringified_channel_list_still_names_its_channels() {
        // The shape weekly_research was stored in.
        assert_eq!(destination_list(&json!("[\"google_chat\"]")), vec!["google_chat"]);
        assert_eq!(
            destination_list(&json!("[\"spaces/AAQAxxxx\"]")),
            vec!["spaces/AAQAxxxx"]
        );
        // The proper shape, unchanged.
        assert_eq!(destination_list(&json!(["google_chat", "slack"])), vec!["google_chat", "slack"]);
        // A bare name is one destination; blanks and non-lists are none.
        assert_eq!(destination_list(&json!("google_chat")), vec!["google_chat"]);
        assert!(destination_list(&json!("")).is_empty());
        assert!(destination_list(&json!(["", ""])).is_empty());
        assert!(destination_list(&json!(null)).is_empty());
        assert!(destination_list(&json!({"a": 1})).is_empty());
        // A string that starts with '[' but is not JSON is taken literally,
        // not dropped.
        assert_eq!(destination_list(&json!("[not json")), vec!["[not json"]);
    }
}

#[cfg(test)]
mod sanitize_tests {
    use super::*;

    #[test]
    fn strips_paired_think_tags() {
        let out = sanitize_result_text("<think>planning here</think>\n# Report\nBody");
        assert_eq!(out, "# Report\nBody");
    }

    #[test]
    fn strips_untagged_reasoning_preamble_before_heading() {
        // The exact leak class: free-form CoT prose, then the report title.
        let input = "The user is providing the context of a scheduled Heartbeat \
                     Task. I need to fulfill this. I am Mesh, the coordinator. \
                     Plan: write the report. Let's write.\n\n\
                     # Deep Research Report: Agentic AI\nSummary\nBody text.";
        let out = sanitize_result_text(input);
        assert!(out.starts_with("# Deep Research Report"), "got: {out:?}");
        assert!(!out.contains("I am Mesh"), "reasoning leaked: {out:?}");
    }

    #[test]
    fn keeps_report_that_starts_with_title() {
        let input = "# Deep Research Report\nSummary\nThe user base grew.";
        // "the user" appears in body but there's no pre-heading preamble → keep.
        assert_eq!(sanitize_result_text(input), input);
    }

    #[test]
    fn self_check_does_not_flag_graph_signals_noop() {
        // Real history row: status=success, error "" (empty), 74ms.
        assert_eq!(classify_run_issue("graph_signals", "success", Some(74), Some(""), None), None);
        for a in ["cluster_health", "rag_reindex", "security_audit", "agent_self_check"] {
            assert_eq!(classify_run_issue(a, "success", Some(74), None, None), None, "{a}");
        }
    }

    #[test]
    fn self_check_still_flags_real_errors_and_fast_expensive_actions() {
        let e = classify_run_issue("graph_signals", "error", Some(74), Some("boom"), None).unwrap();
        assert_eq!(e, "error: boom");
        // non-empty error field on a "success" row still shows
        assert!(classify_run_issue("graph_signals", "success", Some(5000), Some("x"), None).is_some());
        // status error with empty message is still an error
        assert_eq!(
            classify_run_issue("cluster_health", "error", None, Some(""), None).unwrap(),
            "error: (no message)"
        );
        // silent-failure check stays for expensive actions
        let f = classify_run_issue("research", "success", Some(74), Some(""), None).unwrap();
        assert_eq!(f, "suspiciously fast: 74ms (likely silent failure)");
        assert_eq!(classify_run_issue("research", "success", Some(4000), None, None), None);
    }

    #[test]
    fn security_risk_ignores_routine_mcp_calls() {
        let rows = vec![
            ("mcp_tool_call".to_string(), 629),
            ("config_update".to_string(), 8),
        ];
        assert_eq!(security_risk_level(&rows, 5), "LOW");
        let mut bad = rows.clone();
        bad.push(("exec_denied".to_string(), 1));
        assert_eq!(security_risk_level(&bad, 5), "MEDIUM");
        bad.push(("exec_denied".to_string(), 4));
        assert_eq!(security_risk_level(&bad, 5), "HIGH", "5 exec_denied is a burst");
    }

    #[test]
    fn security_risk_is_proportionate_to_volume() {
        let r = |v: &[(&str, i64)]| -> Vec<(String, i64)> {
            v.iter().map(|(t, c)| (t.to_string(), *c)).collect()
        };
        // live numbers: 3 auth failures, no MCP traffic
        assert_eq!(security_risk_level(&r(&[("auth_failure", 3)]), 5), "LOW");
        assert_eq!(
            security_risk_level(&r(&[("auth_failure", 3), ("rate_limit", 2)]), 5),
            "LOW"
        );
        // meaningful volume, not yet a flood
        assert_eq!(security_risk_level(&r(&[("auth_failure", 12)]), 5), "MEDIUM");
        // a burst
        assert_eq!(security_risk_level(&r(&[("auth_failure", 60)]), 5), "HIGH");
        assert_eq!(
            security_risk_level(&r(&[("auth_failure", 30), ("cluster_auth_failure", 20)]), 5),
            "HIGH"
        );
        assert_eq!(security_risk_level(&r(&[("path_traversal", 5)]), 5), "HIGH");
        assert_eq!(security_risk_level(&r(&[("path_traversal", 1)]), 5), "MEDIUM");
        // unknown event types still count, with volume bands
        assert_eq!(security_risk_level(&r(&[("some_new_event", 4)]), 5), "LOW");
        assert_eq!(security_risk_level(&r(&[("some_new_event", 100)]), 5), "HIGH");
        // a zero threshold must not make everything HIGH
        assert_eq!(security_risk_level(&r(&[]), 0), "LOW");
    }

    #[test]
    fn self_check_exempts_retention_and_rotation() {
        for a in ["agent_messages_retention", "audit_log_rotate"] {
            assert_eq!(classify_run_issue(a, "success", Some(8), None, None), None, "{a}");
            assert!(classify_run_issue(a, "error", Some(8), Some("x"), None).is_some());
        }
    }

    #[test]
    fn fast_thought_experiment_is_trusted_only_when_it_says_it_did_nothing() {
        for t in [
            "Skipped: 1 active session(s) \u{2014} organic traversals being captured",
            "Thought experiment: not enough connected entities in graph (2, need 3). Ingest more documents first.",
            "Thought experiment: no new queries this run \u{2014} all sampled entity pairs were rehearsed within the revisit window.",
        ] {
            assert_eq!(
                classify_run_issue("thought_experiment", "success", Some(8), None, Some(t)),
                None,
                "{t}"
            );
        }
        // fast, claims to have run: still suspicious
        let done = "Thought experiment complete: 5 queries run, 0 traversals captured, 0 entities discovered.";
        assert!(classify_run_issue("thought_experiment", "success", Some(403), None, Some(done)).is_some());
        // fast, no text at all: still suspicious
        assert!(classify_run_issue("thought_experiment", "success", Some(8), None, None).is_some());
        assert!(classify_run_issue("thought_experiment", "success", Some(8), None, Some("")).is_some());
    }

    #[test]
    fn keeps_short_legit_intro_without_reasoning_markers() {
        let input = "This quarter's findings are below.\n\n# Report\nBody.";
        // No reasoning markers → do not strip the intro.
        assert_eq!(sanitize_result_text(input), input);
    }

    #[test]
    fn noop_when_no_heading() {
        let input = "Let me think. The user wants X. Here is the answer inline.";
        // No markdown heading → can't safely locate report start → leave as-is.
        assert_eq!(sanitize_result_text(input), input);
    }
}

// ─── backup_knowledge ──────────────────────────────────────────────────
//
// Ported 2026-08-12 (third name-based mis-tier): exports docs / entities /
// edges (and optionally conversations) to dated JSONL snapshots. Same SQL
// row shapes as the Python pageindex_store export_* methods, so a restore
// tool written against the old files keeps working. Files written are
// reported through the NativeOutcome artifact channel (the write_log
// precedent). Failure semantics per the design: the DOCS export failing
// is an error (the backup did not happen); the optional sections append
// an explicit failure note instead of silently exporting less.

async fn action_backup_knowledge(
    state: &std::sync::Arc<crate::state::AppState>,
    config: &Value,
) -> Result<NativeOutcome, String> {
    use std::io::Write;

    let output_dir = config
        .get("output_dir")
        .and_then(|v| v.as_str())
        .unwrap_or("/data/backups");
    let include_graph = config.get("include_graph").and_then(|v| v.as_bool()).unwrap_or(true);
    let include_conversations = config
        .get("include_conversations")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Same guard as Python: snapshots only under /data or /tmp. Checked on
    // the LEXICALLY normalized path — the target dir may not exist yet, so
    // canonicalize() can't run, and ".." segments are rejected outright.
    if output_dir.contains("..") {
        return Err(format!("backup_knowledge: output_dir must not contain '..' (got {output_dir})"));
    }
    if !(output_dir.starts_with("/data/") || output_dir == "/data"
        || output_dir.starts_with("/tmp/") || output_dir == "/tmp")
    {
        return Err(format!(
            "backup_knowledge: output_dir must be under /data/ or /tmp/ (got {output_dir})"
        ));
    }

    let date_str = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let backup_dir = std::path::Path::new(output_dir).join(&date_str);
    std::fs::create_dir_all(&backup_dir)
        .map_err(|e| format!("backup_knowledge: cannot create {}: {e}", backup_dir.display()))?;

    fn write_jsonl(path: &std::path::Path, rows: &[Value]) -> Result<(), String> {
        let mut f = std::fs::File::create(path)
            .map_err(|e| format!("create {}: {e}", path.display()))?;
        for r in rows {
            writeln!(f, "{r}").map_err(|e| format!("write {}: {e}", path.display()))?;
        }
        Ok(())
    }

    let mut artifacts: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // Docs — the core section; its failure fails the run.
    let docs: Vec<(uuid::Uuid, Option<String>, Option<String>, Option<String>, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
            "SELECT doc_id, source_uri, title, hash, created_at FROM docs ORDER BY created_at",
        )
        .fetch_all(&state.db)
        .await
        .map_err(|e| format!("backup_knowledge: docs export failed: {e}"))?;
    let doc_rows: Vec<Value> = docs
        .iter()
        .map(|(id, uri, title, hash, created)| {
            json!({
                "doc_id": id.to_string(), "source_uri": uri, "title": title,
                "hash": hash, "created_at": created.map(|t| t.to_rfc3339()),
            })
        })
        .collect();
    let doc_file = backup_dir.join("docs.jsonl");
    write_jsonl(&doc_file, &doc_rows).map_err(|e| format!("backup_knowledge: {e}"))?;
    artifacts.push(doc_file.display().to_string());

    let mut entity_count = 0usize;
    let mut edge_count = 0usize;
    if include_graph {
        match sqlx::query_as::<_, (uuid::Uuid, Option<String>, Option<String>, Option<Value>, Option<chrono::DateTime<chrono::Utc>>)>(
            "SELECT entity_id, canonical_name, type, aliases_json, created_at FROM entities ORDER BY canonical_name",
        )
        .fetch_all(&state.db)
        .await
        {
            Ok(entities) => {
                let rows: Vec<Value> = entities.iter().map(|(id, name, ty, aliases, created)| {
                    json!({
                        "entity_id": id.to_string(), "canonical_name": name, "type": ty,
                        "aliases": aliases, "created_at": created.map(|t| t.to_rfc3339()),
                    })
                }).collect();
                let f = backup_dir.join("entities.jsonl");
                write_jsonl(&f, &rows).map_err(|e| format!("backup_knowledge: {e}"))?;
                entity_count = rows.len();
                artifacts.push(f.display().to_string());
            }
            Err(e) => notes.push(format!("entities export FAILED: {e}")),
        }
        match sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid, Option<String>, uuid::Uuid, Option<Value>, Option<chrono::DateTime<chrono::Utc>>)>(
            "SELECT edge_id, src_entity_id, rel_type, dst_entity_id, evidence_json, created_at FROM edges ORDER BY created_at",
        )
        .fetch_all(&state.db)
        .await
        {
            Ok(edges) => {
                let rows: Vec<Value> = edges.iter().map(|(id, src, rel, dst, ev, created)| {
                    json!({
                        "edge_id": id.to_string(), "src_entity_id": src.to_string(),
                        "rel_type": rel, "dst_entity_id": dst.to_string(),
                        "evidence": ev, "created_at": created.map(|t| t.to_rfc3339()),
                    })
                }).collect();
                let f = backup_dir.join("edges.jsonl");
                write_jsonl(&f, &rows).map_err(|e| format!("backup_knowledge: {e}"))?;
                edge_count = rows.len();
                artifacts.push(f.display().to_string());
            }
            Err(e) => notes.push(format!("edges export FAILED: {e}")),
        }
    }

    let mut conv_count = 0usize;
    if include_conversations {
        match sqlx::query_scalar::<_, Value>(
            "SELECT COALESCE(jsonb_agg(row_to_json(c)), '[]'::jsonb) FROM \
             (SELECT * FROM noo_conversations ORDER BY started_at DESC LIMIT 10000) c",
        )
        .fetch_one(&state.db)
        .await
        {
            Ok(Value::Array(rows)) => {
                let f = backup_dir.join("conversations.jsonl");
                write_jsonl(&f, &rows).map_err(|e| format!("backup_knowledge: {e}"))?;
                conv_count = rows.len();
                artifacts.push(f.display().to_string());
            }
            Ok(_) => notes.push("conversations export FAILED: unexpected shape".to_string()),
            Err(e) => notes.push(format!("conversations export FAILED: {e}")),
        }
    }

    // Snapshots age out. These files hold names, titles and edge evidence of
    // people who may later be erased (right to be forgotten), and the erase
    // cannot reach into them, so their life is bounded instead: a dated
    // snapshot directory older than `retention_days` (default 30, the same
    // window as the erase archive) is removed on every run. Only directories
    // named exactly `YYYY-MM-DD` are ever touched.
    let retention_days = config
        .get("retention_days")
        .and_then(|v| v.as_i64())
        .unwrap_or(BACKUP_RETENTION_DAYS)
        .clamp(1, BACKUP_RETENTION_DAYS_MAX);
    match prune_expired_backups(std::path::Path::new(output_dir), chrono::Utc::now().date_naive(), retention_days) {
        Ok(n) if n > 0 => notes.push(format!("pruned {n} snapshot(s) older than {retention_days}d")),
        Ok(_) => {}
        // A snapshot that could not be removed is a retention failure worth
        // seeing, but not one that un-does the backup that just succeeded.
        Err(e) => notes.push(format!("snapshot pruning FAILED: {e}")),
    }

    let mut text = format!(
        "Backup knowledge: exported {} doc(s), {entity_count} entit(ies), {edge_count} edge(s)",
        doc_rows.len()
    );
    if include_conversations {
        text.push_str(&format!(", {conv_count} conversation(s)"));
    }
    text.push_str(&format!(" to {}.", backup_dir.display()));
    if !notes.is_empty() {
        text.push_str(&format!(" WARNINGS: {}", notes.join("; ")));
    }
    Ok(NativeOutcome { text, artifacts, ..Default::default() })
}

/// How long a `backup_knowledge` snapshot directory is kept by default, and
/// the most a task may ask for. Not "forever": see the pruning note in
/// [`action_backup_knowledge`].
const BACKUP_RETENTION_DAYS: i64 = 30;
const BACKUP_RETENTION_DAYS_MAX: i64 = 90;

/// The snapshot directory names (`YYYY-MM-DD`) older than `keep_days` before
/// `today`. A name that is not exactly a date in that form is never returned,
/// so a hand-made `old-stuff` or `2026-1-5` directory is left alone.
pub(crate) fn expired_backup_dirs(names: &[String], today: chrono::NaiveDate, keep_days: i64) -> Vec<String> {
    names
        .iter()
        .filter(|n| {
            chrono::NaiveDate::parse_from_str(n, "%Y-%m-%d")
                .ok()
                .filter(|d| d.format("%Y-%m-%d").to_string() == **n)
                .is_some_and(|d| (today - d).num_days() > keep_days)
        })
        .cloned()
        .collect()
}

/// Remove the expired dated snapshot directories under `root`. Returns how
/// many went. A symlink named like a date is skipped, never followed.
fn prune_expired_backups(root: &std::path::Path, today: chrono::NaiveDate, keep_days: i64) -> Result<usize, String> {
    let names: Vec<String> = std::fs::read_dir(root)
        .map_err(|e| format!("read {}: {e}", root.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir() && !t.is_symlink()))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    let mut removed = 0;
    for name in expired_backup_dirs(&names, today, keep_days) {
        std::fs::remove_dir_all(root.join(&name)).map_err(|e| format!("remove {name}: {e}"))?;
        removed += 1;
    }
    Ok(removed)
}

// ─── rag_reindex ───────────────────────────────────────────────────────
//
// See the RUST_NATIVE_ACTIONS entry for the history. It used to submit a
// `background_embed` job; that job type is retired (job_types.rs
// RETIRED_JOB_TYPES): it drained conversation memory, not the pages it
// counted, and trellion's PageIndexEmbedder already embeds pages and chunks
// on its own loop. The action keeps its name (seeded tasks run it every few
// hours) and now CHECKS that the backlog drains, raising when it does not —
// a heartbeat action that reports a problem as success is the failure mode
// this file exists to avoid.

async fn action_rag_reindex(
    state: &std::sync::Arc<crate::state::AppState>,
    _config: &Value,
) -> Result<String, String> {
    let verdict = crate::autonomy_evaluators::embed_backlog_status(state).await?;
    rag_reindex_outcome(&verdict)
}

/// The action's answer for a backlog verdict — pure, so every arm is tested.
fn rag_reindex_outcome(v: &crate::autonomy_evaluators::EmbedBacklog) -> Result<String, String> {
    use crate::autonomy_evaluators::EmbedBacklog as B;
    match *v {
        B::Clear => Ok("RAG reindex: all pages and chunks are embedded. No action needed.".to_string()),
        B::NoEmbedder { now } => Err(format!(
            "RAG reindex: {now} page(s)/chunk(s) are unembedded and the trellion add-on, \
             which embeds them, is not enabled — nothing will drain this backlog"
        )),
        B::Watching { now, prev: None } => Ok(format!(
            "RAG reindex: {now} page(s)/chunk(s) unembedded; trellion's embedder drains them. \
             Baseline recorded — the next run judges progress."
        )),
        B::Watching { now, prev: Some(prev) } => Ok(format!(
            "RAG reindex: {now} page(s)/chunk(s) unembedded (was {prev}); trellion's embedder \
             drains them. Progress is judged once the {}m window has passed.",
            crate::autonomy_evaluators::EMBED_BACKLOG_STALL_SECS / 60
        )),
        B::Draining { prev, now } => Ok(format!(
            "RAG reindex: backlog draining — {now} page(s)/chunk(s) unembedded, down from {prev}."
        )),
        B::Stalled { prev, now, since_secs } => Err(format!(
            "RAG reindex: the embedding backlog is not draining — {now} page(s)/chunk(s) \
             unembedded, {prev} about {}m ago. Check trellion's embedder: `noo stack logs trellion`",
            since_secs / 60
        )),
    }
}

// ─── self_benchmark ────────────────────────────────────────────────────
//
// Tier B per the design, ported 2026-08-12. Not a prompt but a
// measurement harness: run each configured test prompt through the
// coordinator, record latency, score the response against expected
// keywords, and summarize — the summary string matches the Python
// handler byte-for-byte in shape. Each call records its token usage
// same as the research retry path.

async fn action_self_benchmark(
    state: &std::sync::Arc<crate::state::AppState>,
    config: &Value,
    task_id: &str,
) -> Result<String, String> {
    let default_prompts = json!([
        {"prompt": "What is 2+2?", "expected_keywords": ["4"], "category": "math"},
        {"prompt": "Summarize: The sky is blue because of Rayleigh scattering.",
         "expected_keywords": ["scattering", "blue"], "category": "comprehension"},
    ]);
    let prompts = config
        .get("test_prompts")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_else(|| default_prompts.as_array().unwrap().clone());
    let timeout_secs = config.get("timeout").and_then(|v| v.as_u64()).unwrap_or(30);

    let mut latencies: Vec<f64> = Vec::new();
    let mut qualities: Vec<f64> = Vec::new();

    for (i, spec) in prompts.iter().enumerate() {
        let prompt = spec.get("prompt").and_then(|v| v.as_str()).unwrap_or("");
        if prompt.is_empty() {
            continue;
        }
        let expected: Vec<String> = spec
            .get("expected_keywords")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|k| k.as_str().map(str::to_lowercase))
                    .collect()
            })
            .unwrap_or_default();

        let conversation_id = format!("heartbeat-{task_id}-selfbench-{}-{i}", uuid::Uuid::new_v4());
        let start = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            crate::bus_principal::with_principal(
        crate::bus_principal::unattended_principal(crate::heartbeat_actions::HEARTBEAT_CONVERSATION_OWNER),
        crate::coordinator::run(
                state,
                prompt,
                &conversation_id,
                "heartbeat",
                5, // benchmark prompts are single-step; a small cap bounds cost
                None,
                Some(HEARTBEAT_CONVERSATION_OWNER),
            ),
    ),
        )
        .await;

        match outcome {
            Ok(Ok(cr)) => {
                crate::usage::record(
                    state.db.clone(),
                    cr.node.clone(),
                    cr.backend.clone(),
                    cr.model.clone(),
                    "heartbeat",
                    crate::usage::UsageActor::consumer("self_benchmark"),
                    cr.usage.prompt_tokens,
                    cr.usage.completion_tokens,
                );
                let latency = start.elapsed().as_secs_f64();
                let response = cr.response.to_lowercase();
                let quality = if expected.is_empty() {
                    1.0
                } else {
                    let matched = expected.iter().filter(|k| response.contains(*k)).count();
                    matched as f64 / expected.len() as f64
                };
                latencies.push(latency);
                qualities.push(quality);
            }
            Ok(Err(e)) => {
                tracing::warn!(prompt_index = i, error = %e, "self_benchmark_prompt_failed");
                latencies.push(start.elapsed().as_secs_f64());
                qualities.push(0.0);
            }
            Err(_) => {
                latencies.push(timeout_secs as f64);
                qualities.push(0.0);
            }
        }
    }

    if latencies.is_empty() {
        return Ok("Self benchmark: no results.".to_string());
    }
    let n = latencies.len();
    let avg_latency = latencies.iter().sum::<f64>() / n as f64;
    let avg_quality = qualities.iter().sum::<f64>() / n as f64;
    let pass = qualities.iter().filter(|q| **q >= 0.5).count();
    Ok(format!(
        "Self benchmark: {n} prompts — avg {avg_latency:.1}s latency, \
         quality {pass}/{n} pass. Avg quality score: {:.0}%",
        avg_quality * 100.0
    ))
}

// ─── channel_keepalive ─────────────────────────────────────────────────
//
// Ported from Python 2026-08-11 (Tier A). The Python version
// asked the in-process ChannelManager adapters `is_connected()` — adapters
// that no longer receive traffic since channels moved to Rust, so it
// measured a leftover. This version probes the CHANNEL APIS themselves:
// telegram getMe validates the bot token end-to-end, google_chat mints a
// service-account token (the same credential every send uses). Any failed
// channel makes the action Err → status=error in noo_heartbeat_runs
// (a failed check must never record success).

async fn action_channel_keepalive(config: &Value) -> Result<SystemReport, String> {
    let channels: Vec<String> = config
        .get("channels")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let send_test = config.get("send_test").and_then(|v| v.as_bool()).unwrap_or(false);

    if channels.is_empty() {
        return Ok(SystemReport {
            lines: vec!["Channel keepalive: no channels configured.".to_string()],
            detail: Vec::new(),
        });
    }

    // `results` is the full per-channel status for the run record and the
    // error column; `general` is what a channel may carry — the verdict
    // word, never the probe's raw error or a bot handle.
    let mut results: Vec<String> = Vec::new();
    let mut general: Vec<String> = Vec::new();
    let mut failures = 0usize;

    for ch in &channels {
        let keys = crate::routes::communication::CHANNEL_ENV_KEYS
            .iter()
            .find(|(name, _)| name == ch)
            .map(|(_, keys)| *keys);
        let Some(keys) = keys else {
            results.push(format!("{ch} UNKNOWN_CHANNEL"));
            failures += 1;
            continue;
        };
        let configured = keys.iter().any(|k| crate::config::secret_env::secret_opt(k).is_some());
        if !configured {
            results.push(format!("{ch} NOT_CONFIGURED"));
            failures += 1;
            continue;
        }

        let mut status = match probe_channel(ch).await {
            Ok(s) => s,
            Err(e) => {
                failures += 1;
                format!("FAILED ({e})")
            }
        };

        if send_test && !status.starts_with("FAILED") {
            let recipient = config
                .get(format!("{ch}_test_recipient"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !recipient.is_empty() {
                match crate::routes::communication::send_channel_message(
                    ch,
                    recipient,
                    "[Heartbeat keepalive test]",
                    None,
                    None,
                    None,
                )
                .await
                {
                    Ok(()) => status = format!("{status}, test sent"),
                    Err(e) => {
                        failures += 1;
                        status = format!("FAILED (test send: {e})");
                    }
                }
            }
        }
        general.push(format!("{ch} {}", status.split(" (").next().unwrap_or(&status)));
        results.push(format!("{ch} {status}"));
    }

    let summary = format!("Channel keepalive: {}", results.join(", "));
    if failures > 0 {
        Err(summary)
    } else {
        Ok(SystemReport {
            lines: vec![format!("Channel keepalive: {}", general.join(", "))],
            detail: vec![summary],
        })
    }
}

/// Live credential probe per channel. Returns a short status string on
/// success, Err with the reason otherwise. whatsapp has no cheap
/// validation call wired here yet — the honest answer is CONFIGURED with
/// the caveat, not a fake OK.
async fn probe_channel(channel: &str) -> Result<String, String> {
    match channel {
        "telegram" => {
            let token = crate::config::secret_env::secret_required("TELEGRAM_BOT_TOKEN")?;
            let url = format!("https://api.telegram.org/bot{token}/getMe");
            let resp = crate::tls::client_builder()
                .build()
                .map_err(|e| format!("http client: {}", crate::redact::scrub(&e.to_string())))?
                .get(&url)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
                .map_err(|e| format!("unreachable: {}", crate::redact::scrub(&e.to_string())))?;
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or_default();
            if body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                let bot = body
                    .pointer("/result/username")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                Ok(format!("OK (@{bot})"))
            } else {
                Err(format!(
                    "auth failed: HTTP {status} {}",
                    body.get("description").and_then(|v| v.as_str()).unwrap_or("")
                ))
            }
        }
        "google_chat" => match crate::google_auth::chat_access_token().await {
            Ok(_) => Ok("OK (token minted)".to_string()),
            Err(e) => Err(format!("auth failed: {e}")),
        },
        "whatsapp" => Ok("CONFIGURED (no live probe implemented)".to_string()),
        other => Err(format!("no probe for channel '{other}'")),
    }
}

// ─── model_cache_warm ──────────────────────────────────────────────────
//
// Ported from Python 2026-08-11 (Tier A). Same endpoints the
// Python version called, now in process (`local_get/post`)
// — and with a cached-check that matches what
// /api/models/cached actually returns. Python compared
// `(m["model"], m["node_id"])` against a response whose entries carry
// `name` + `nodes: [hostnames]`, so the cached set was always empty and
// every tick re-pulled everything.

async fn action_model_cache_warm(
    state: &crate::state::AppState,
    config: &Value,
) -> Result<String, String> {
    let empty: Vec<Value> = Vec::new();
    let models = config
        .get("models")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    if models.is_empty() {
        return Ok("Model cache warm: no models configured.".to_string());
    }

    // (model_name → node hostnames it is cached on)
    let mut cached: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    if let Ok(data) = local_get(state, "/api/models/cached").await {
        if let Some(list) = data.get("models").and_then(|v| v.as_array()) {
            for m in list {
                let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if name.is_empty() {
                    continue;
                }
                let nodes = m
                    .get("nodes")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter().filter_map(|n| n.as_str().map(str::to_string)).collect()
                    })
                    .unwrap_or_default();
                cached.insert(name.to_string(), nodes);
            }
        }
    }

    let mut already = 0usize;
    let mut pulling = 0usize;
    let mut errors: Vec<String> = Vec::new();

    for spec in models {
        let model = spec.get("model").and_then(|v| v.as_str()).unwrap_or("");
        if model.is_empty() {
            continue;
        }
        let node_id = spec.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
        let backend = spec.get("backend").and_then(|v| v.as_str()).unwrap_or("ollama");

        let is_cached = cached.get(model).is_some_and(|nodes| {
            node_id.is_empty() || nodes.iter().any(|n| n == node_id)
        });
        if is_cached {
            already += 1;
            continue;
        }

        let mut body = json!({"model": model, "backend": backend});
        if !node_id.is_empty() {
            body["node_id"] = json!(node_id);
        }
        match local_post(state, "/api/models/pull", &body).await {
            Ok(_) => {
                pulling += 1;
                tracing::info!(model = %model, node = %node_id, "heartbeat_model_pull");
            }
            Err(e) => errors.push(format!("{model}: {e}")),
        }
    }

    let summary = format!(
        "Model cache warm: {already}/{} already cached, pulling {pulling} model(s){}",
        models.len(),
        if errors.is_empty() {
            ".".to_string()
        } else {
            format!("; {} pull(s) FAILED: {}", errors.len(), errors.join("; "))
        }
    );
    // A tick where every attempted pull failed is an error, not a report.
    if !errors.is_empty() && pulling == 0 {
        Err(summary)
    } else {
        Ok(summary)
    }
}

#[cfg(test)]
mod tier_a_routing_tests {
    use super::*;

    // Routing: these must no longer reach Python — the assertion that
    // fails if a rebase drops them from RUST_NATIVE_ACTIONS.
    #[test]
    fn keepalive_and_cache_warm_are_rust_native() {
        assert_eq!(action_path("channel_keepalive"), ActionPath::RustNative);
        assert_eq!(action_path("model_cache_warm"), ActionPath::RustNative);
    }

    #[test]
    fn rag_reindex_is_rust_native() {
        assert_eq!(action_path("rag_reindex"), ActionPath::RustNative);
    }

    #[test]
    fn rag_reindex_raises_when_the_backlog_cannot_or_does_not_drain() {
        use crate::autonomy_evaluators::EmbedBacklog as B;
        // The two failure verdicts must be Err — a heartbeat action that
        // reports "not draining" as success is a silent success.
        let stalled = rag_reindex_outcome(&B::Stalled { prev: 40, now: 41, since_secs: 7200 });
        assert!(stalled.as_ref().is_err_and(|e| e.contains("not draining") && e.contains("120m")), "{stalled:?}");
        let off = rag_reindex_outcome(&B::NoEmbedder { now: 9 });
        assert!(off.as_ref().is_err_and(|e| e.contains("not enabled")), "{off:?}");
        // Everything else is an honest Ok that names the numbers.
        assert!(rag_reindex_outcome(&B::Clear).is_ok());
        assert!(rag_reindex_outcome(&B::Draining { prev: 40, now: 3 }).is_ok_and(|m| m.contains("down from 40")));
        assert!(rag_reindex_outcome(&B::Watching { now: 5, prev: None }).is_ok_and(|m| m.contains("Baseline")));
        assert!(rag_reindex_outcome(&B::Watching { now: 5, prev: Some(6) }).is_ok_and(|m| m.contains("was 6")));
    }

    #[test]
    fn backup_knowledge_is_rust_native() {
        assert_eq!(action_path("backup_knowledge"), ActionPath::RustNative);
    }

    #[test]
    fn tier_b_routing() {
        assert_eq!(action_path("goal_review"), ActionPath::RustLlm);
        assert_eq!(action_path("self_benchmark"), ActionPath::RustNative);
        // Re-tiered to C on port day: graph sampling + retrieval rehearsal
        // is Trellion work, whatever the design's first pass said. And
        // continue_pending_tasks stays put pending the Python-session
        // honesty audit.
        for a in ["thought_experiment", "continue_pending_tasks"] {
            assert_eq!(action_path(a), ActionPath::PythonDelegate, "{a}");
        }
    }

    #[test]
    fn goal_review_prompt_and_short_circuit() {
        use serde_json::json;
        let cfg = json!({"goals": [
            {"name": "Ship v1", "description": "finish the port", "status": "active"}
        ]});
        let p = build_action_prompt_inner("goal_review", "t", &cfg);
        assert!(p.contains("**Ship v1**"), "got: {p}");
        assert!(p.contains("status: active"));
        assert!(goal_review_no_goals("goal_review", &cfg).is_none());
        assert_eq!(
            goal_review_no_goals("goal_review", &json!({})).as_deref(),
            Some("Goal review: no goals configured.")
        );
        assert!(goal_review_no_goals("daily_briefing", &json!({})).is_none());
    }
}

#[cfg(test)]
mod cron_tests {
    use super::*;
    use chrono::{Datelike, TimeZone, Weekday};

    /// The schedule-edit route refuses with this parser's reason, and what it accepts is what
    /// `compute_next_run` can fire: one parser, not two that can disagree.
    #[test]
    fn parse_cron_is_the_parser_the_scheduler_fires_from() {
        assert!(parse_cron("30 3 * * *").is_ok(), "the backup runbook's own example");
        assert!(parse_cron("  0 9 * * 1  ").is_ok(), "surrounding space is not an error");
        for bad in ["not a cron", "61 3 * * *", "30 3 * *", ""] {
            let err = parse_cron(bad).expect_err(bad);
            assert!(!err.is_empty(), "{bad:?} must carry the parser's reason");
            assert!(
                compute_next_run(bad, Utc::now(), chrono_tz::UTC).is_none(),
                "{bad:?}: the route refuses exactly what the scheduler cannot fire"
            );
        }
        assert!(compute_next_run("30 3 * * *", Utc::now(), chrono_tz::UTC).is_some());
    }

    #[test]
    fn normalize_prepends_seconds_and_shifts_dow() {
        assert_eq!(normalize_cron("0 9 * * 1"), "0 0 9 * * 2"); // Mon stays Mon
        assert_eq!(normalize_cron("0 17 * * 1-5"), "0 0 17 * * 2-6"); // weekdays
        assert_eq!(normalize_cron("0 8 * * *"), "0 0 8 * * *");
        assert_eq!(normalize_cron("*/30 * * * *"), "0 */30 * * * *");
    }

    #[test]
    fn dow_translation_edge_cases() {
        assert_eq!(translate_unix_dow("0"), "1"); // Unix Sunday
        assert_eq!(translate_unix_dow("7"), "1"); // Unix Sunday (alt)
        assert_eq!(translate_unix_dow("6"), "7"); // Saturday
        assert_eq!(translate_unix_dow("1,3,5"), "2,4,6");
        assert_eq!(translate_unix_dow("1-5/2"), "2-6/2");
        assert_eq!(translate_unix_dow("MON-FRI"), "MON-FRI"); // names pass through
        assert_eq!(translate_unix_dow("*"), "*");
    }

    #[test]
    fn research_prompt_directs_papers_and_paraphrase() {
        let cfg = serde_json::json!({"topic": "agentic AI", "depth": "deep"});
        for action in ["research_report", "research_and_send"] {
            let p = build_action_prompt_inner(action, "AI Research Review", &cfg);
            assert!(p.contains("agentic AI"), "{action}: topic missing");
            assert!(p.contains("primary sources"), "{action}: no primary-source steer");
            assert!(p.contains("papers"), "{action}: papers not mentioned");
            assert!(p.to_lowercase().contains("paraphrase"), "{action}: paraphrase missing");
            assert!(p.contains("OWN words"), "{action}: own-words steer missing");
            // Must steer toward NEW external work and away from the KB's own
            // past reports (the stale-repetition root cause).
            assert!(p.contains("NEW external"), "{action}: new-external steer missing");
            assert!(p.to_lowercase().contains("local knowledge base"), "{action}: KB caveat missing");
            assert!(p.contains("noo_rag_query"), "{action}: rag caveat missing");
            // 'deep' → 4 searches; placeholder must be substituted, not literal.
            assert!(p.contains("4 searches"), "{action}: search count not substituted");
            assert!(!p.contains("{searches}"), "{action}: literal placeholder leaked");
            // The shared tool note reaches every research prompt (it lives in
            // a const) and asks for a search query to stay ONE argument.
            assert!(p.contains("is ONE"), "{action}: tool note missing");
            assert!(!p.contains("{{...}}"), "{action}: doubled braces leaked");
        }
    }

    #[test]
    fn monday_cron_fires_on_monday() {
        // 2026-06-12 is a Friday. "0 9 * * 1" must land on Monday
        // 2026-06-15, not Sunday (the bug this guards against).
        let from = chrono::Utc.with_ymd_and_hms(2026, 6, 12, 16, 0, 0).unwrap();
        let next = compute_next_run("0 9 * * 1", from, chrono_tz::UTC).unwrap();
        assert_eq!(next.weekday(), Weekday::Mon);
        assert_eq!((next.year(), next.month(), next.day()), (2026, 6, 15));
    }

    #[test]
    fn weekday_range_fires_friday_not_sunday() {
        // From Friday morning, "0 17 * * 1-5" (Mon-Fri 5pm) fires the
        // same Friday — the unshifted Quartz reading skipped to Sunday.
        let from = chrono::Utc.with_ymd_and_hms(2026, 6, 12, 9, 0, 0).unwrap();
        let next = compute_next_run("0 17 * * 1-5", from, chrono_tz::UTC).unwrap();
        assert_eq!(next.weekday(), Weekday::Fri);
        assert_eq!((next.year(), next.month(), next.day()), (2026, 6, 12));
    }
}

#[cfg(test)]
mod write_log_tests {
    use super::*;
    use serde_json::json;

    // Routing: write_log must no longer reach Python. This is the assertion
    // that would fail if a rebase dropped it from RUST_NATIVE_ACTIONS.
    #[test]
    fn write_log_is_rust_native() {
        assert_eq!(action_path("write_log"), ActionPath::RustNative);
    }

    #[test]
    fn unported_actions_still_delegate() {
        // Guard against over-broad edits to the allowlist: these are Tier C
        // (genuine ML) and must stay on the Python path.
        {
            let a = "graph_signals";
            assert_eq!(action_path(a), ActionPath::PythonDelegate, "{a}");
        }
    }

    #[test]
    fn renders_header_and_sections_in_order() {
        let sections = vec!["cluster".to_string(), "rag".to_string()];
        let gathered = vec!["- **Nodes**: 2/2 online".to_string(), "- **Documents**: 7".to_string()];
        let out = render_log("Nightly Log", &sections, &gathered, "2026-08-01 09:00:00 UTC");

        assert!(out.starts_with("# Heartbeat Log"));
        assert!(out.contains("**Task**: Nightly Log"));
        assert!(out.contains("**Sections**: cluster, rag"));
        // Headings are title-cased and content follows its own heading.
        let cluster_at = out.find("## Cluster").expect("cluster heading");
        let rag_at = out.find("## Rag").expect("rag heading");
        assert!(cluster_at < rag_at, "sections must render in config order");
        assert!(out[cluster_at..rag_at].contains("2/2 online"));
        assert!(out[rag_at..].contains("- **Documents**: 7"));
    }

    #[test]
    fn missing_optional_fields_render_as_na() {
        // Python emitted the literal "N/A" for absent completed/failed.
        let v = json!({"queue_depth": 3});
        assert_eq!(num_field(&v, "queue_depth"), 3);
        assert_eq!(num_field(&v, "absent"), 0);
        assert_eq!(opt_field(&v, "absent"), "N/A");
        assert_eq!(opt_field(&v, "queue_depth"), "3");
    }

    #[test]
    fn title_case_matches_python_str_title() {
        assert_eq!(title_case("cluster"), "Cluster");
        assert_eq!(title_case("rag"), "Rag");
        assert_eq!(title_case(""), "");
    }

    // The unconfigured-workspace fallback. Python returned "/tmp" rather than
    // failing, and an artifact-writing action that hard-fails on a default
    // install would be worse than one writing to /tmp.
    #[test]
    fn workspace_path_empty_when_disabled() {
        let ws = crate::config::WorkspaceConfig {
            host: "/mnt/d/AgentWorkspace".into(),
            mount: "/workspace".into(),
            enabled: false,
        };
        assert_eq!(ws.path(), "");
    }

    #[test]
    fn workspace_path_defaults_mount_when_enabled() {
        let ws = crate::config::WorkspaceConfig {
            host: "/mnt/d/AgentWorkspace".into(),
            mount: String::new(),
            enabled: true,
        };
        assert_eq!(ws.path(), "/workspace");
        let ws2 = crate::config::WorkspaceConfig {
            host: String::new(),
            mount: "/custom".into(),
            enabled: true,
        };
        assert_eq!(ws2.path(), "/custom");
    }

    // NativeOutcome is the new artifact channel; a plain String action must
    // keep reporting no artifacts so existing handlers are unaffected.
    #[test]
    fn string_actions_carry_no_artifacts() {
        let o: NativeOutcome = "done".to_string().into();
        assert_eq!(o.text, "done");
        assert!(o.artifacts.is_empty());
    }
}

#[cfg(test)]
mod database_backup_tests {
    use serde_json::json;

    /// Both tests below point `NOO_HOST_SPOOL_DIR` somewhere; env is process-wide.
    static SPOOL_ENV: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Queuing must return AT ONCE and must not report success: the dump is
    /// still to come. The old action slept 5 s between polls for up to 120 s,
    /// then failed the run while hostd was still dumping.
    #[tokio::test]
    async fn queuing_returns_immediately_and_does_not_record_success() {
        let _env = SPOOL_ENV.lock().await;
        let dir = std::env::temp_dir().join(format!("backup-queue-{}", uuid::Uuid::new_v4()));
        // SAFETY: serialised by SPOOL_ENV against the only other test that sets it.
        unsafe {
            std::env::set_var("NOO_HOST_SPOOL_DIR", &dir);
        }
        let started = std::time::Instant::now();
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            super::action_database_backup(&json!({"wait_secs": 120})),
        )
        .await
        .expect("queuing waited for the dump instead of returning")
        .expect("queuing into a writable spool must succeed");
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        assert!(out.pending, "a queued backup is pending, not a finished success");
        let waiting_on = crate::backup_completion::pending_result_path(&out.text)
            .expect("the run text must name the result file the hook waits on");
        assert!(waiting_on.ends_with(".result.json"), "{waiting_on}");
        let queued: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert!(queued.iter().any(|n| n.ends_with(".cmd.json")), "the backup command must be in the spool: {queued:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The #247 contract, moved here from
    /// `tests/test_heartbeat.py::test_database_backup_raises_when_spool_unavailable`
    /// when the action was ported to Rust.
    ///
    /// A spool write that fails must produce `Err`. Returning a descriptive
    /// string instead records `status=success`, which is exactly how a broken
    /// backup stayed invisible for 17 days.
    #[tokio::test]
    async fn spool_unavailable_is_an_error_not_a_success_string() {
        let _env = SPOOL_ENV.lock().await;
        // Point the spool at a path that cannot be created: /dev/null is a
        // file, so mkdir beneath it fails on every platform we ship.
        // SAFETY: set_var is unsafe in edition 2024; this test is
        // single-threaded w.r.t. this variable and restores nothing because
        // no other test reads NOO_HOST_SPOOL_DIR.
        unsafe {
            std::env::set_var("NOO_HOST_SPOOL_DIR", "/dev/null/not-a-dir");
        }

        let res = super::action_database_backup(&json!({})).await;

        let Err(err) = res else { panic!("a failed spool write must not report success") };
        assert!(
            err.contains("FAILED to queue"),
            "error must name the queue failure, got: {err}"
        );
    }
}

#[cfg(test)]
mod usage_rollup_tests {
    use super::{parse_usage_partition, usage_rollup_cutoff};

    #[test]
    fn partition_parser_accepts_only_the_generated_shape() {
        assert_eq!(parse_usage_partition("noo_token_usage_2026_08"), Some((2026, 8)));
        assert_eq!(parse_usage_partition("noo_token_usage_2026_12"), Some((2026, 12)));
        // Everything else is skipped, never guessed at — a wrong parse here
        // feeds a month into the DROP path.
        assert_eq!(parse_usage_partition("noo_token_usage_2026_13"), None);
        assert_eq!(parse_usage_partition("noo_token_usage_2026_00"), None);
        assert_eq!(parse_usage_partition("noo_token_usage_2026_8"), None);
        assert_eq!(parse_usage_partition("noo_token_usage_26_08"), None);
        assert_eq!(parse_usage_partition("noo_token_usage_1999_01"), None);
        assert_eq!(parse_usage_partition("noo_token_usage_backup"), None);
        assert_eq!(parse_usage_partition("noo_token_usage_monthly"), None);
        assert_eq!(parse_usage_partition("noo_security_audit_2026_08"), None);
        assert_eq!(parse_usage_partition("noo_token_usage_2026_08_extra"), None);
    }

    #[test]
    fn cutoff_keeps_the_trailing_raw_window() {
        // months_raw=3 at 2026-08: May is the oldest raw month; anything
        // strictly before it rolls.
        let cutoff = usage_rollup_cutoff(2026, 8, 3);
        assert_eq!(cutoff, (2026, 5));
        assert!((2026, 4) < cutoff, "April rolls");
        assert!((2026, 5) >= cutoff, "May stays raw");
        assert!((2026, 8) >= cutoff, "the current month stays raw");
    }

    #[test]
    fn cutoff_crosses_year_boundaries() {
        assert_eq!(usage_rollup_cutoff(2026, 2, 3), (2025, 11));
        assert_eq!(usage_rollup_cutoff(2026, 1, 1), (2025, 12));
        assert_eq!(usage_rollup_cutoff(2026, 12, 12), (2025, 12));
        // months_raw=0: only the in-progress month stays raw.
        assert_eq!(usage_rollup_cutoff(2026, 8, 0), (2026, 8));
    }
}

// ─── idle_scaledown candidate selection ───────────
//
// These fixtures are shaped like the REAL `GET /api/cluster/backends`
// payload, because the bug being fixed was precisely a disagreement about
// that shape: the action read `node`, the route emits `node_id`. A test
// against an invented payload would have passed while the action was a
// guaranteed no-op in production for its entire life.
#[cfg(test)]
mod idle_scaledown_tests {
    use super::idle_backend_candidates;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;

    /// Exactly the field set `routes/cluster.rs::cluster_backends` emits,
    /// after `annotate_backend_activity` adds `pinned` + `last_inference_ts`.
    fn backend(node: &str, bt: &str, last: Option<i64>, pinned: bool) -> serde_json::Value {
        let mut v = json!({
            "node_id": node,
            "backend": bt,
            "backend_type": bt,
            "model": "qwen3:8b",
            "status": "running",
            "hostname": node,
            "load": 0.01,
            "pinned": pinned,
        });
        if let Some(ts) = last {
            v["last_inference_ts"] = json!(ts);
        }
        v
    }

    #[test]
    fn reads_node_id_not_node() {
        // The original defect: with `node` as the key, this candidate was
        // dropped for an empty node name and the action always reported
        // "no idle backends found".
        let backends = vec![backend("host8", "ollama", Some(NOW - 3600), false)];
        assert_eq!(
            idle_backend_candidates(&backends, NOW, 600),
            vec![("host8".to_string(), "ollama".to_string())]
        );
    }

    #[test]
    fn missing_timestamp_is_unknown_never_idle() {
        // The far worse half of the defect: absence used to mean "idle", and
        // the field was absent from EVERY row — a working version 1 would
        // have stopped the whole cluster on its first run.
        let backends = vec![
            backend("host8", "ollama", None, false),
            backend("host1", "vllm", None, false),
        ];
        assert!(idle_backend_candidates(&backends, NOW, 600).is_empty());
    }

    #[test]
    fn recent_inference_is_not_idle() {
        let backends = vec![backend("host8", "ollama", Some(NOW - 60), false)];
        assert!(idle_backend_candidates(&backends, NOW, 600).is_empty());
        // Exactly at the threshold counts as idle; one second under does not.
        let at = vec![backend("host8", "ollama", Some(NOW - 600), false)];
        assert_eq!(idle_backend_candidates(&at, NOW, 600).len(), 1);
        let under = vec![backend("host8", "ollama", Some(NOW - 599), false)];
        assert!(idle_backend_candidates(&under, NOW, 600).is_empty());
    }

    #[test]
    fn pinned_backends_are_never_candidates() {
        // A declared placement is restarted by the node-agent reconciler:
        // stopping it is a flap, not a scaledown.
        let backends = vec![backend("host8", "vllm", Some(NOW - 86_400), true)];
        assert!(idle_backend_candidates(&backends, NOW, 600).is_empty());
    }
}

#[cfg(test)]
mod delivery_envelope_tests {
    use super::delivery_result;

    /// An adapter refusal is not delivery, and its reason survives — the
    /// exact error observed on 2026-09-20, when a report the operator never
    /// saw was stored as delivered.
    #[test]
    fn a_refusal_is_not_delivery() {
        let err = delivery_result(Err("Google Chat API error 404 Not Found".into())).unwrap_err();
        assert!(err.contains("did not deliver"), "{err}");
        assert!(err.contains("404"), "the adapter's reason must survive: {err}");
    }

    #[test]
    fn a_successful_send_is_delivery() {
        assert!(delivery_result(Ok(())).is_ok());
    }

    /// A refusal with no reason must still fail rather than reading as
    /// success because the detail was missing.
    #[test]
    fn a_refusal_without_detail_still_fails() {
        let err = delivery_result(Err(String::new())).unwrap_err();
        assert!(err.contains("no detail"), "{err}");
    }
}

/// the heartbeat and operator-alert paths reach the gateway
/// IN PROCESS. Each used to be an HTTPS self-call signed with the controller
/// HMAC (`caller=heartbeat` / `operator_alert`), which is what kept
/// `cluster_hmac_non_inference` non-zero on host8. A self-call added back —
/// by URL, by the loopback client, or by the HMAC header — fails here.
#[cfg(test)]
mod no_self_call_tests {
    /// The file with its `#[cfg(test)] mod … { … }` blocks cut out: the
    /// tests name the patterns they forbid. Brace counting is enough here —
    /// a test body's braces balance.
    fn src(name: &str) -> String {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name);
        let text = std::fs::read_to_string(&p).unwrap();
        let mut out = String::new();
        let mut rest = text.as_str();
        while let Some(at) = rest.find("#[cfg(test)]\nmod ") {
            out.push_str(&rest[..at]);
            let block = &rest[at..];
            let open = block.find('{').expect("a test module body");
            let mut depth = 0usize;
            let mut end = block.len();
            for (i, c) in block[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            rest = &block[end..];
        }
        out.push_str(rest);
        out
    }

    #[test]
    fn heartbeat_and_operator_alert_make_no_http_self_call() {
        let mut scanned = 0;
        for file in ["heartbeat_actions.rs", "heartbeat_loop.rs", "operator_alert.rs", "routes/intelligence.rs"] {
            let code = src(file);
            assert!(code.contains("fn "), "{file}: scanned nothing");
            scanned += 1;
            for forbidden in [
                // Split so the repo-wide scan in mcp_local.rs does not find
                // this guard itself.
                concat!("cluster_hmac_auth", "_header("),
                "loopback_client(",
                "https://127.0.0.1",
                "/api/channels/send\")",
                "/api/v1/docs/ingest\")",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "{file} contains `{forbidden}` — a gateway self-call over HTTP; call the handler in process"
                );
            }
        }
        assert_eq!(scanned, 4);
    }

    /// Every path a heartbeat action reads has an in-process handler; an
    /// unknown path is an error, never a quiet fall back to HTTP.
    #[test]
    fn the_in_process_table_refuses_an_unknown_path() {
        let code = src("heartbeat_actions.rs");
        let mut used = Vec::new();
        for (needle, close) in [("local_get(state, \"", '"'), ("local_post(state, \"", '"')] {
            for part in code.split(needle).skip(1) {
                used.push(part.split(close).next().unwrap().to_string());
            }
        }
        assert!(!used.is_empty(), "found no in-process calls — the scan is wrong");
        for path in used {
            assert!(
                code.contains(&format!("\"{path}\" =>")),
                "{path} is called but has no arm in local_get/local_post"
            );
        }
    }
}

#[cfg(test)]
mod report_delivery_message_tests {
    use super::report_delivery_message;

    #[test]
    fn drive_link_gives_a_pointer_not_the_body() {
        let msg = report_delivery_message("Weekly", "# Report\n\nbody", Some("https://drive/x"));
        assert!(msg.contains("Full report: https://drive/x"), "{msg}");
        assert!(!msg.contains("body"));
    }

    #[test]
    fn no_drive_link_sends_the_report_itself_and_never_claims_an_attachment() {
        // No adapter carries `file_path`; a message that says "attached"
        // is a delivery claim with nothing behind it.
        let body = "# Report\n\n".to_string() + &"line of findings\n".repeat(400);
        let msg = report_delivery_message("Weekly", &body, None);
        assert_eq!(msg, body);
        assert!(!msg.to_ascii_lowercase().contains("attached"));
    }
}

#[cfg(test)]
mod prior_research_tests {
    use chrono::TimeZone;

    #[test]
    fn the_search_window_never_shrinks_below_thirty_days() {
        let d = |m: u32, day: u32| chrono::Utc.with_ymd_and_hms(2026, m, day, 1, 0, 0).unwrap();
        let now = d(10, 1);
        // A manual run yesterday: the window is 30 days, not one.
        assert_eq!(super::search_cutoff(d(9, 30), now), d(9, 1));
        // A report older than 30 days: search from it, as before.
        assert_eq!(super::search_cutoff(d(8, 20), now), d(8, 20));
    }

    #[test]
    fn junk_success_rows_are_not_fed_forward_as_prior_research() {
        let at = |d: u32| chrono::Utc.with_ymd_and_hms(2026, 9, d, 12, 0, 0).unwrap();
        let report = |t: &str| format!(
            "# AI\n\n## Summary\n{t} shifted toward local-first inference this quarter.\n\n## Key Findings\n- **{t}** runs on consumer GPUs\n\n{}",
            (1..40).map(|i| format!("Finding {i} about {t} and the field.\n")).collect::<String>()
        );
        let rows = vec![
            (at(28), "thought\n".repeat(1041)),                                        // the loop
            (at(27), format!("thought\n{}", (1..90).map(|i| format!("Step {i}: I will search and plan.\n")).collect::<String>())), // planning only
            (at(26), format!("# AI\n{}", "Searching for sources now.\n".repeat(120))),  // a loop with a heading: cleaning keeps it, only the quality gate refuses it
            (at(22), report("Gemma")),
            (at(21), format!("thought\nPlanning.\n{}", report("Qwen"))),              // reasoning, then a real report
            (at(20), report("Llama")),
        ];
        let got = super::usable_prior_summaries(rows, 3);
        let days: Vec<u32> = got.iter().map(|(w, _)| chrono::Datelike::day(w)).collect();
        assert_eq!(days, vec![22, 21, 20], "junk skipped, and the three real ones still fill the block: {got:?}");
        assert!(got.iter().all(|(_, s)| !s.to_lowercase().contains("thought")), "{got:?}");
    }
}

#[cfg(test)]
mod backup_retention_tests {
    use chrono::NaiveDate;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// `backup_knowledge` snapshots held erased people's names
    /// and evidence and were never removed. Dated directories older than the
    /// window go; newer ones, and anything not named exactly as a date, stay.
    #[test]
    fn dated_snapshots_older_than_the_window_expire_and_nothing_else_does() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 4).unwrap();
        let got = super::expired_backup_dirs(
            &names(&["2026-08-01", "2026-09-04", "2026-09-03", "2026-10-04", "old-stuff", "2026-9-1", "2026-13-40", "notes.txt"]),
            today,
            30,
        );
        // 30 days before 10-04 is 09-04: kept (the window is "30 days", inclusive); 09-03 is 31 days old.
        assert_eq!(got, ["2026-08-01", "2026-09-03"]);
    }

    #[test]
    fn pruning_removes_expired_directories_from_disk_and_leaves_the_rest() {
        let root = std::env::temp_dir().join(format!("noo_backup_prune_{}", uuid::Uuid::new_v4()));
        for d in ["2026-01-01", "2026-10-03", "keep-me"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
            std::fs::write(root.join(d).join("docs.jsonl"), "{}").unwrap();
        }
        std::fs::write(root.join("2026-01-02"), "a file named like a date").unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 10, 4).unwrap();
        assert_eq!(super::prune_expired_backups(&root, today, 30).unwrap(), 1);
        let mut left: Vec<String> =
            std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        left.sort();
        assert_eq!(left, ["2026-01-02", "2026-10-03", "keep-me"], "a plain file and a non-date directory are untouched");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
