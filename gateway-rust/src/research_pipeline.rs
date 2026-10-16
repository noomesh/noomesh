// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Phased deep-research pipeline for the heartbeat research actions
//! (`research_report`, `research_and_send`).
//!
//! The single-shot shape — one agentic loop whose final turn must write the
//! entire 6-17k-char report — cannot work on a local model: the report and
//! the `<think>` block share one `max_tokens` output budget (~4096), so the
//! model either never exits the think block (Empty) or gets truncated
//! mid-report (TooShort). Both failed the quality gate daily.
//!
//! This module gives the task the deep-research shape instead:
//!
//!   1. GATHER  — the agentic loop with tools (thinking OFF since 2026-09-29:
//!                on gemma-4 the "thinking" is plain `thought` text through
//!                the non-streaming path and became the whole turn, so no
//!                tool ever ran), whose deliverable is structured source
//!                notes plus a numbered section outline, NOT the report.
//!   2. WRITE   — one bounded LLM call per outline section (thinking OFF —
//!                nobody reads it and every think token starves the visible
//!                text), each with the full output budget and the notes in
//!                front of it. Failed sections get one corrective retry.
//!   3. ASSEMBLE — concatenate usable sections; the caller's existing
//!                whole-report quality gate still applies.
//!
//! Any structural failure (gather error, unparseable outline, too few
//! usable sections) returns `Err` and the caller falls back to the
//! single-shot path — the pipeline can only ever be an improvement, never
//! a new way to produce nothing.

use crate::state::AppState;

/// One planned report section, parsed from the gather phase's outline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionSpec {
    pub title: String,
    /// One-line description of what the section covers (may be empty).
    pub brief: String,
}

/// Outline size guidance per depth. A range, not a hard count — the model
/// plans the sections; we only bound how many we'll accept.
fn outline_size_hint(depth: &str) -> &'static str {
    match depth.to_lowercase().as_str() {
        "brief" => "4 sections",
        "deep" => "6-7 sections",
        "exhaustive" => "7-9 sections",
        _ => "5-6 sections",
    }
}

/// Per-section length guidance. Each section is its own LLM call with the
/// full output budget, so these are comfortably achievable — and together
/// they add up to the depth's whole-report target.
fn section_length_hint(depth: &str) -> &'static str {
    match depth.to_lowercase().as_str() {
        "brief" => "120-250 words",
        "deep" => "250-450 words",
        "exhaustive" => "300-550 words",
        _ => "180-350 words",
    }
}

/// Build the gather-phase prompt: research with tools, deliver notes + an
/// outline. Reuses the single-shot sourcing rules (primary sources, no RAG,
/// own words, no noo_inference) — only the deliverable shape differs.
pub fn build_gather_prompt(topic: &str, depth: &str, instructions: &str) -> String {
    let searches = crate::heartbeat_actions::depth_search_count(depth).to_string();
    let sourcing = crate::heartbeat_actions::RESEARCH_SOURCING.replace("{searches}", &searches);
    let size = outline_size_hint(depth);
    let mut prompt = format!(
        "You are running the GATHER phase of a {depth} research task on: {topic}. \
         In this phase you research and PLAN the report; the report itself is \
         written section-by-section in a later phase from your notes.\n\n\
         {sourcing}\n\n\
         {tool_format}\n\n\
         Deliverable — your final answer must be EXACTLY these two markdown \
         blocks and nothing else:\n\n\
         ## Notes\n\
         One top-level bullet per source, formatted `- [S1] Title — venue/author \
         — date — URL`, each followed by indented sub-bullets capturing the \
         concrete findings you extracted from it: numbers, named systems, claims, \
         results. Cover at least {min_sources} DISTINCT sources — run more \
         searches with new angles if your first ones return fewer. These notes \
         are the ONLY source material the writing phase sees, so anything not \
         captured here is lost — be thorough and specific.\n\n\
         ## Outline\n\
         A numbered plan of {size} for the report. One line per section, \
         formatted `1. Section Title — one-line brief of what it covers`. The \
         first section must be `Summary` and the last must be `Sources`. Order \
         the middle sections so the report reads as one argument, not a list.\n\n\
         Do NOT write the report itself in this phase — notes and outline only.",
        tool_format = crate::heartbeat_actions::RESEARCH_TOOL_FORMAT,
        min_sources = min_sources(depth),
    );
    if !instructions.is_empty() {
        prompt.push_str(&format!("\n\nAdditional instructions: {instructions}"));
    }
    prompt
}

/// Parse the `## Outline` block out of the gather deliverable.
///
/// Two accepted shapes, tried in order:
///   1. Numbered list (what the prompt asks for): `1. Title — brief`,
///      `2) Title: brief`, ending at the next heading.
///   2. Heading-style (what gemma actually produces despite the prompt —
///      observed live 2026-08-20): `##`/`###` heading lines are the
///      sections, an optional leading `# Report Title` line is skipped,
///      and the bullet lines under each heading become its brief.
///
/// Returns None when no outline heading is found or when neither shape
/// yields 3..=10 sections (too few to be a report plan, too many to be
/// worth one LLM call each).
pub fn parse_outline(gather_text: &str) -> Option<Vec<SectionSpec>> {
    // Find the outline heading (last one wins if the model echoed the
    // instructions — the deliverable comes after the echo).
    let mut outline_start: Option<usize> = None;
    for (i, line) in gather_text.lines().enumerate() {
        let t = line.trim().to_lowercase();
        if t.starts_with('#') && t.contains("outline") {
            outline_start = Some(i);
        }
    }
    let start = outline_start?;
    let accept = |sections: Vec<SectionSpec>| {
        if (3..=10).contains(&sections.len()) {
            Some(sections)
        } else {
            None
        }
    };
    accept(parse_numbered_outline(gather_text, start))
        .or_else(|| accept(parse_heading_outline(gather_text, start)))
}

/// Shape 1: numbered entries after the outline heading; the next heading
/// ends the block.
fn parse_numbered_outline(gather_text: &str, start: usize) -> Vec<SectionSpec> {
    let mut sections = Vec::new();
    for line in gather_text.lines().skip(start + 1) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        // A new heading ends the outline block.
        if t.starts_with('#') {
            break;
        }
        // Numbered entry: `1. ...` / `1) ...`
        let rest = t
            .strip_prefix(|c: char| c.is_ascii_digit())
            .map(|r| r.trim_start_matches(|c: char| c.is_ascii_digit()))
            .and_then(|r| r.strip_prefix('.').or_else(|| r.strip_prefix(')')));
        let Some(entry) = rest else {
            // Non-numbered line inside the block (stray prose) — skip it.
            continue;
        };
        let entry = entry.trim().trim_matches('*').trim();
        if entry.is_empty() {
            continue;
        }
        let (title, brief) = split_title_brief(entry);
        if title.is_empty() {
            continue;
        }
        sections.push(SectionSpec { title, brief });
    }
    sections
}

/// Shape 2: `##`/`###` headings after the outline heading ARE the
/// sections; a `# `-level line (the report title the model volunteered)
/// is skipped; bullets under a heading are folded into its brief so the
/// section writer keeps the model's own plan for that section.
fn parse_heading_outline(gather_text: &str, start: usize) -> Vec<SectionSpec> {
    let mut sections: Vec<SectionSpec> = Vec::new();
    for line in gather_text.lines().skip(start + 1) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(heading) = t.strip_prefix("##") {
            let title = heading.trim_start_matches('#').trim().trim_matches('*').trim();
            if !title.is_empty() {
                sections.push(SectionSpec { title: title.to_string(), brief: String::new() });
            }
            continue;
        }
        if t.starts_with('#') {
            // `# Report Title` — the model's own title line, not a section.
            continue;
        }
        // Bullet or prose under the current section heading → brief.
        if let Some(last) = sections.last_mut() {
            let item = t.trim_start_matches(['*', '-', '+']).trim();
            if !item.is_empty() && last.brief.chars().count() < 200 {
                if !last.brief.is_empty() {
                    last.brief.push_str("; ");
                }
                last.brief.push_str(item);
            }
        }
    }
    sections
}

/// Split `Title — brief` (also ` - ` and `: ` separators) into parts.
fn split_title_brief(entry: &str) -> (String, String) {
    for sep in ["—", " - ", ": "] {
        if let Some(idx) = entry.find(sep) {
            let title = entry[..idx].trim().trim_matches('*').trim();
            let brief = entry[idx + sep.len()..].trim();
            if !title.is_empty() {
                return (title.to_string(), brief.to_string());
            }
        }
    }
    (entry.trim().to_string(), String::new())
}

/// Build the write-phase prompt for one section. The notes are the sole
/// source material; the full outline is included so the section knows its
/// place in the whole and doesn't restate its neighbours.
pub fn build_section_prompt(
    topic: &str,
    depth: &str,
    notes: &str,
    outline: &[SectionSpec],
    index: usize,
    written_so_far: &[String],
) -> String {
    let section = &outline[index];
    let outline_list = outline
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let marker = if i == index { " ← YOU ARE WRITING THIS ONE" } else { "" };
            if s.brief.is_empty() {
                format!("{}. {}{}", i + 1, s.title, marker)
            } else {
                format!("{}. {} — {}{}", i + 1, s.title, s.brief, marker)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let length = section_length_hint(depth);
    let is_sources = section.title.to_lowercase().contains("source")
        || section.title.to_lowercase().contains("reference");
    let body_guidance = if is_sources {
        "Output the full reference list from the notes: one bullet per source \
         with title, venue/author, date, and URL. Nothing else."
            .to_string()
    } else {
        format!(
            "Write {length} of finished report prose for THIS section only. \
             Use concrete findings from the notes — numbers, named systems, \
             attributed claims (cite as [S1], [S2] matching the notes). Do not \
             invent facts that are not in the notes, do not restate what other \
             sections cover, and do not summarise the report as a whole. Do \
             not include a references, sources or bibliography list — the \
             Sources section at the end carries it; cite inline only."
        )
    };
    // Every section sees the same notes, so without a view of what is already
    // written each one re-explains the same two or three findings (a 2026-09-29
    // report restated one trio of sources in all five sections). The digest
    // is the opening of each earlier section — enough to know its points.
    let prior = if is_sources || written_so_far.is_empty() {
        String::new()
    } else {
        let digest = written_so_far
            .iter()
            .map(|w| {
                let head: String = w.chars().take(PRIOR_SECTION_DIGEST_CHARS).collect();
                if w.chars().count() > PRIOR_SECTION_DIGEST_CHARS { format!("{head}…") } else { head }
            })
            .collect::<Vec<_>>()
            .join("\n\n");
        format!(
            "Already written (do NOT repeat these points — build on them or use \
             different findings from the notes):\n{digest}\n\n"
        )
    };
    format!(
        "You are writing ONE section of a {depth} research report on: {topic}.\n\n\
         Report outline:\n{outline_list}\n\n\
         Research notes (your ONLY source material):\n{notes}\n\n\
         {prior}\
         Write section {num}: \"{title}\".\n{body_guidance}\n\n\
         Output format — begin IMMEDIATELY with the heading `## {title}` and \
         then the section content. No preamble, no self-description, no \
         narration about the process, no other sections, no closing remarks. \
         Do NOT call any tools — everything you need is in the notes above.",
        num = index + 1,
        title = section.title,
    )
}

/// How much of each earlier section a later one sees (see `build_section_prompt`).
const PRIOR_SECTION_DIGEST_CHARS: usize = 500;

/// Distinct sources a gather deliverable should cover, by depth. Below this
/// the gather gets one retry; see `run_research_pipeline`.
fn min_sources(depth: &str) -> usize {
    match depth.to_lowercase().as_str() {
        "brief" => 3,
        "deep" => 7,
        "exhaustive" => 9,
        _ => 5,
    }
}

/// Count distinct `[S<n>]` source bullets in the notes (top-level bullets
/// only, so an inline citation of an existing source does not count twice).
fn count_sources(notes: &str) -> usize {
    let re = regex::Regex::new(r"(?m)^\s*[-*]\s*\[S(\d+)\]").expect("static regex");
    re.captures_iter(notes)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect::<std::collections::HashSet<_>>()
        .len()
}

fn is_sources_title(title: &str) -> bool {
    let t = title.to_lowercase();
    t.contains("source") || t.contains("reference") || t.contains("bibliograph")
}

/// Give the outline the shape the prompt asks for, whatever the model
/// returned: `Summary` first and `Sources` last. On 2026-09-29 the model
/// planned neither; with no Sources section two prose sections wrote their
/// own reference lists mid-report.
fn normalize_outline(mut outline: Vec<SectionSpec>) -> Vec<SectionSpec> {
    let has_summary = outline
        .first()
        .map(|s| s.title.to_lowercase().contains("summary"))
        .unwrap_or(false);
    if !has_summary {
        outline.insert(0, SectionSpec {
            title: "Summary".into(),
            brief: "the headline findings of the report".into(),
        });
    }
    // A sources section planned in the middle moves to the end.
    if let Some(pos) = outline.iter().position(|s| is_sources_title(&s.title)) {
        let s = outline.remove(pos);
        outline.push(s);
    } else {
        outline.push(SectionSpec { title: "Sources".into(), brief: String::new() });
    }
    outline
}

/// Drop a reference list a prose section wrote anyway: from a line that is
/// only "References" / "Sources" / "Bibliography" (optionally a heading or
/// bold, optionally with a colon) to the end of the section.
fn strip_stray_reference_list(text: &str) -> String {
    let re = regex::Regex::new(
        r"(?im)^[ \t]*(?:#{1,6}[ \t]*)?(?:\*\*)?(?:references|sources|bibliography)[ \t]*:?[ \t]*(?:\*\*)?[ \t]*:?[ \t]*$",
    )
    .expect("static regex");
    match re.find(text) {
        Some(m) => text[..m.start()].trim_end().to_string(),
        None => text.to_string(),
    }
}

/// Minimum usable visible chars for one section. Sources lists are short
/// by nature; prose sections below ~250 chars are stubs.
fn section_min_chars(section: &SectionSpec) -> usize {
    let t = section.title.to_lowercase();
    if t.contains("source") || t.contains("reference") {
        100
    } else {
        250
    }
}

/// Run the phased pipeline. Returns the assembled report text, or `Err`
/// when the pipeline could not produce one structurally (the caller falls
/// back to the single-shot path — this must never be a new way to fail
/// silently).
///
/// `conversation_id` is the run's base id; phases get suffixed ids
/// (`-gather`, `-s1`…) so each is its own conversation and none inherits
/// another's context window.
#[allow(clippy::too_many_arguments)]
/// Write pipeline progress into the task's `running` run row so long runs
/// are legible from history ("what phase is it in?") instead of only from
/// logs. Keyed by (task_id, status='running') — the in-flight guard
/// guarantees at most one such row per task. Best-effort: the run's
/// completion overwrites result_text either way.
async fn note_phase(state: &AppState, task_id: &str, phase: &str) {
    let _ = sqlx::query(
        "UPDATE noo_heartbeat_runs SET result_text = $2          WHERE task_id = $1 AND status = 'running'",
    )
    .bind(task_id)
    .bind(format!("[in progress] {phase}"))
    .execute(&state.db)
    .await;
}

pub async fn run_research_pipeline(
    state: &AppState,
    action: &str,
    task_id: &str,
    topic: &str,
    depth: &str,
    instructions: &str,
    conversation_id: &str,
    max_iterations: u32,
    model: Option<&str>,
) -> anyhow::Result<String> {
    // ── Phase 1: gather ────────────────────────────────────────────
    note_phase(state, task_id, "phase 1/3: gathering sources + outline").await;
    let gather_prompt = build_gather_prompt(topic, depth, instructions);
    // Same cumulative-research enrichment the single-shot prompt gets:
    // prior-run summaries steer the gather searches toward new ground.
    let gather_prompt = crate::heartbeat_actions::enrich_research_prompt_with_history(
        gather_prompt,
        &state.db,
        action,
        task_id,
    )
    .await;

    // Thinking OFF, like the section writes: on gemma-4 the reasoning
    // arrives as plain text with a bare `thought` prefix, and through the
    // non-streaming path that text IS the turn — the model narrated its
    // plan for 865 chars, called no tool, and stopped (2026-09-29,
    // weekly_research, twice in a row). Fresh conversation per run: the
    // stable `-gather` id carried every earlier run's turns, and the model
    // answered "I've already performed several web searches in the
    // conversation history" instead of searching.
    let gather_conversation = format!(
        "{conversation_id}-gather-{}",
        &uuid::Uuid::new_v4().to_string()[..8]
    );
    let gather = crate::bus_principal::with_principal(
        crate::bus_principal::unattended_principal(crate::heartbeat_actions::HEARTBEAT_CONVERSATION_OWNER),
        crate::coordinator::run_with_thinking(
        state,
        &gather_prompt,
        &gather_conversation,
        "heartbeat",
        max_iterations,
        model,
        Some(crate::heartbeat_actions::HEARTBEAT_CONVERSATION_OWNER),
        false,
    ),
    )
    .await?;
    record_usage(state, &gather);
    let mut gather_calls = gather.tool_calls.clone();
    let gather_text = crate::heartbeat_actions::sanitize_result_text(&gather.response);

    // One corrective retry when the gather deliverable is unusable — the
    // same recovery shape the sections and the single-shot path already
    // have, previously missing here. Both real failure modes are covered:
    // stall narration ("I am initiating four searches…" — 8-21) and the
    // loop ending on a tool sub-answer instead of the deliverable (8-22).
    // The sources were already gathered in the failed attempt's tool
    // turns, so a report-only re-prompt usually recovers.
    // A deliverable that parses but covers too few sources gets the same one
    // retry: the 2026-09-29 report had three, and every section restated them.
    // The retry never makes things worse — a short-but-usable first attempt is
    // kept when the retry is no better.
    let need = min_sources(depth);
    let first = gather_deliverable(&gather_text);
    let first_sources = first.as_ref().map(|(_, n)| count_sources(n)).unwrap_or(0);
    let (outline, notes) = match first {
        Ok(ok) if first_sources >= need => ok,
        first => {
            let too_few = first.is_ok();
            let first_reason = match &first {
                Ok(_) => format!("only {first_sources} distinct sources in the notes, need {need}"),
                Err(e) => e.clone(),
            };
            tracing::warn!(
                action,
                reason = %first_reason,
                raw_chars = gather_text.chars().count(),
                quality = ?crate::verify::response::classify_response_quality(&gather_text, 600),
                "research_pipeline_gather_unusable_retrying"
            );
            let retry_prompt = if too_few {
                format!(
                    "{gather_prompt}\n\n\
                     ⚠️ RETRY: your notes cover only {first_sources} distinct \
                     sources; this report needs at least {need}. Run more \
                     web_search queries with NEW angles (never repeat a query), \
                     then output the two blocks again — `## Notes` listing EVERY \
                     source, the earlier ones and the new ones, followed by \
                     `## Outline`."
                )
            } else {
                format!(
                    "{gather_prompt}\n\n\
                     ⚠️ RETRY: your previous attempt did NOT produce the gather \
                     deliverable — it was empty, narrated the process (\"I am \
                     initiating searches…\"), or answered a side question instead. \
                     Output ONLY the two blocks now, beginning immediately with \
                     `## Notes` (one bullet per source with its concrete findings), \
                     followed by `## Outline`. Do not describe what you are doing — \
                     write the notes and outline themselves."
                )
            };
            // Same conversation as the first attempt, so the tool turns it
            // already ran are in view and a notes-only answer is possible;
            // the old `-gather-retry` id was a separate, stable thread that
            // saw none of them.
            let retry = crate::bus_principal::with_principal(
        crate::bus_principal::unattended_principal(crate::heartbeat_actions::HEARTBEAT_CONVERSATION_OWNER),
        crate::coordinator::run_with_thinking(
                state,
                &retry_prompt,
                &gather_conversation,
                "heartbeat",
                max_iterations,
                model,
                Some(crate::heartbeat_actions::HEARTBEAT_CONVERSATION_OWNER),
                false,
            ),
    )
            .await?;
            record_usage(state, &retry);
            gather_calls.extend_from_slice(&retry.tool_calls);
            let retry_text = crate::heartbeat_actions::sanitize_result_text(&retry.response);
            match (first, gather_deliverable(&retry_text)) {
                (Ok(f), Ok(r)) => {
                    if count_sources(&r.1) >= first_sources { r } else { f }
                }
                (Err(_), Ok(r)) => r,
                (Ok(f), Err(_)) => f,
                (Err(_), Err(retry_reason)) => anyhow::bail!(
                    "gather unusable after retry (first: {first_reason}; retry: {retry_reason})"
                ),
            }
        }
    };
    let outline = normalize_outline(outline);
    // Notes the model wrote without one search result behind them are
    // invention with citations — see `web_search_evidence`.
    web_search_evidence(&gather_calls).map_err(|e| anyhow::anyhow!(e))?;
    tracing::info!(
        action,
        sections = outline.len(),
        notes_chars = notes.chars().count(),
        sources = count_sources(&notes),
        "research_pipeline_gather_ok"
    );

    // ── Phase 2: write sections ────────────────────────────────────
    let mut written: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    for (i, section) in outline.iter().enumerate() {
        note_phase(
            state,
            task_id,
            &format!(
                "phase 2/3: writing section {}/{} — {}",
                i + 1,
                outline.len(),
                section.title
            ),
        )
        .await;
        let min = section_min_chars(section);
        let prompt = build_section_prompt(topic, depth, &notes, &outline, i, &written);
        let mut text = run_section(state, &prompt, conversation_id, i, model).await;
        let usable = |t: &str| {
            crate::verify::response::classify_response_quality(t, min).is_usable()
        };
        if !text.as_deref().map(usable).unwrap_or(false) {
            // One corrective retry, same shape as the single-shot retry.
            let retry_prompt = format!(
                "{prompt}\n\n\
                 ⚠️ RETRY: your previous attempt did not produce this section — \
                 it was empty, too short, or narrated the process. Output ONLY \
                 the section now, beginning immediately with `## {}`.",
                section.title
            );
            let retry = run_section(state, &retry_prompt, conversation_id, i, model).await;
            if retry.as_deref().map(usable).unwrap_or(false) {
                text = retry;
            }
        }
        match text {
            Some(t) if usable(&t) => written.push(if is_sources_title(&section.title) {
                t
            } else {
                strip_stray_reference_list(&t)
            }),
            _ => {
                tracing::warn!(section = %section.title, "research_pipeline_section_failed");
                failed.push(section.title.clone());
            }
        }
    }

    // ── Phase 3: assemble ──────────────────────────────────────────
    // A report missing a couple of sections is still a report; one that
    // lost most of its body is not — fall back rather than deliver it.
    if written.len() < 3 || written.len() * 2 < outline.len() {
        anyhow::bail!(
            "only {}/{} sections usable (failed: {})",
            written.len(),
            outline.len(),
            failed.join(", ")
        );
    }
    note_phase(state, task_id, "phase 3/3: assembling report").await;
    let title = topic.trim();
    let report = format!("# {title}\n\n{}", written.join("\n\n"));
    tracing::info!(
        action,
        sections_written = written.len(),
        sections_failed = failed.len(),
        report_chars = report.chars().count(),
        "research_pipeline_assembled"
    );
    Ok(report)
}

/// Did any `web_search` in these coordinator tool calls return results?
///
/// A research run is web research: its report cites the sources its searches
/// found. On 2026-09-30 every search failed (a tool-call parser split the
/// query) and the run still delivered an 8k "report" with [S1]-style
/// citations and precise figures — written from nothing, recorded as
/// success. Err names why, so the run fails with a reason an operator can act
/// on instead of shipping fiction.
pub fn web_search_evidence(tool_calls: &[serde_json::Value]) -> Result<(), String> {
    let searches: Vec<&serde_json::Value> = tool_calls
        .iter()
        .filter(|c| c["name"].as_str() == Some("web_search"))
        .collect();
    if searches.iter().any(|c| c["result"]["success"].as_bool() == Some(true)) {
        return Ok(());
    }
    match searches.first() {
        None => Err("no web_search was run — a research report needs sources".into()),
        Some(first) => Err(format!(
            "every web_search failed ({} attempted) — first error: {}",
            searches.len(),
            first["result"]["error"].as_str().unwrap_or("none recorded")
        )),
    }
}

/// Validate a gather response and split it into (outline, notes).
///
/// Err carries a short human reason (it lands in logs and, after a failed
/// retry, in the fallback error string). Notes = everything before the
/// outline heading; if the model interleaved differently, the full gather
/// text still works as source material. The 200-char notes floor rejects
/// deliverables that planned sections with nothing to write them from.
fn gather_deliverable(gather_text: &str) -> Result<(Vec<SectionSpec>, String), String> {
    let Some(outline) = parse_outline(gather_text) else {
        return Err(format!(
            "no parseable outline ({} chars)",
            gather_text.chars().count()
        ));
    };
    let notes = match gather_text.to_lowercase().rfind("## outline") {
        Some(idx) => gather_text[..idx].trim().to_string(),
        None => gather_text.to_string(),
    };
    if notes.chars().count() < 200 {
        return Err(format!(
            "outline present but only {} chars of notes",
            notes.chars().count()
        ));
    }
    Ok((outline, notes))
}

/// One write-phase call: fresh conversation, thinking OFF, no tool budget
/// needed (2 iterations covers a stray tool attempt + the answer).
async fn run_section(
    state: &AppState,
    prompt: &str,
    conversation_id: &str,
    index: usize,
    model: Option<&str>,
) -> Option<String> {
    match crate::bus_principal::with_principal(
        crate::bus_principal::unattended_principal(crate::heartbeat_actions::HEARTBEAT_CONVERSATION_OWNER),
        crate::coordinator::run_with_thinking(
        state,
        prompt,
        &format!("{conversation_id}-s{}", index + 1),
        "heartbeat",
        2,
        model,
        Some(crate::heartbeat_actions::HEARTBEAT_CONVERSATION_OWNER),
        false,
    ),
    )
    .await
    {
        Ok(cr) => {
            record_usage(state, &cr);
            Some(crate::heartbeat_actions::sanitize_result_text(&cr.response))
        }
        Err(e) => {
            tracing::warn!(error = %e, section = index + 1, "research_pipeline_section_error");
            None
        }
    }
}

/// Token-usage accounting — every pipeline LLM call is its
/// own completion and records itself, matching the single-shot paths.
fn record_usage(state: &AppState, cr: &crate::coordinator::CoordinatorResult) {
    crate::usage::record(
        state.db.clone(),
        cr.node.clone(),
        cr.backend.clone(),
        cr.model.clone(),
        "heartbeat",
        crate::usage::UsageActor::consumer("research"),
        cr.usage.prompt_tokens,
        cr.usage.completion_tokens,
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_research_run_needs_one_search_that_returned_results() {
        use super::web_search_evidence;
        use serde_json::json;
        let failed = |e: &str| json!({"name": "web_search", "arguments": {}, "result": {"success": false, "error": e}});
        let ok = json!({"name": "web_search", "arguments": {"query": "q"}, "result": {"success": true}});
        let rag = json!({"name": "noo_rag_query", "result": {"success": true}});
        // 2026-09-30: three searches, all refused.
        let e = web_search_evidence(&[failed("'query' is required"), failed("'query' is required"), failed("x"), rag.clone()]).unwrap_err();
        assert!(e.contains("every web_search failed (3 attempted)") && e.contains("'query' is required"), "{e}");
        // No search at all — a knowledge-base hit is not web research.
        assert!(web_search_evidence(std::slice::from_ref(&rag)).unwrap_err().contains("no web_search was run"));
        // One success among failures is enough.
        assert!(web_search_evidence(&[failed("202"), ok, rag]).is_ok());
    }

    use super::*;

    #[test]
    fn parse_outline_numbered_em_dash() {
        let text = "## Notes\n- [S1] Paper — arXiv — 2026 — url\n  - finding\n\n\
                    ## Outline\n1. Summary — the headline findings\n\
                    2. Agentic Harnesses — architecture\n\
                    3. 3D Worlds — spatial reasoning\n\
                    4. Sources — references";
        let outline = parse_outline(text).expect("outline should parse");
        assert_eq!(outline.len(), 4);
        assert_eq!(outline[0].title, "Summary");
        assert_eq!(outline[0].brief, "the headline findings");
        assert_eq!(outline[3].title, "Sources");
    }

    #[test]
    fn parse_outline_paren_and_colon_forms() {
        let text = "## Outline\n1) Summary: overview\n2) Body: details\n3) Sources: refs";
        let outline = parse_outline(text).expect("outline should parse");
        assert_eq!(outline.len(), 3);
        assert_eq!(outline[1].title, "Body");
        assert_eq!(outline[1].brief, "details");
    }

    #[test]
    fn parse_outline_missing_heading_is_none() {
        assert!(parse_outline("1. Summary\n2. Body\n3. Sources").is_none());
    }

    #[test]
    fn parse_outline_too_few_sections_is_none() {
        assert!(parse_outline("## Outline\n1. Summary\n2. Sources").is_none());
    }

    #[test]
    fn parse_outline_too_many_sections_is_none() {
        let mut text = String::from("## Outline\n");
        for i in 1..=11 {
            text.push_str(&format!("{i}. Section {i} — brief\n"));
        }
        assert!(parse_outline(&text).is_none());
    }

    #[test]
    fn parse_outline_uses_last_heading_when_instructions_echoed() {
        // Model echoed the instruction text (which contains "## Outline")
        // before the real deliverable — the last heading wins.
        let text = "The plan asks for ## Outline entries.\n\
                    ## Outline\n1. Old — echo\n\n\
                    Here is my deliverable:\n\
                    ## Outline\n1. Summary — a\n2. Body — b\n3. Sources — c";
        let outline = parse_outline(text).expect("outline should parse");
        assert_eq!(outline[0].brief, "a");
    }

    #[test]
    fn parse_outline_stops_at_next_heading() {
        let text = "## Outline\n1. Summary — a\n2. Body — b\n3. Sources — c\n\
                    ## Trailer\n4. Not a section — d";
        let outline = parse_outline(text).expect("outline should parse");
        assert_eq!(outline.len(), 3);
    }

    #[test]
    fn parse_outline_heading_style_gemma_live_sample() {
        // Abbreviated from the real gather output that failed to parse on
        // 2026-08-20: gemma ignored the numbered-list instruction and
        // emitted the outline as markdown headings under a title line.
        let text = "## Notes\n\
                    *   **Source 1**: \"A Survey of Agentic Harnesses\" | arXiv | Aug 2026.\n\
                    \x20   *   Discusses the harness concept.\n\n\
                    ## Outline\n\
                    # Agentic AI Systems in Interactive 3D Worlds\n\n\
                    ## Introduction\n\
                    *   The evolution from scripted NPCs to Agentic AI.\n\
                    *   Problem Statement: The latency/fidelity trade-off.\n\n\
                    ## The Concept of Agentic Harnesses\n\
                    *   Defining the \"Harness\" as coordination middleware.\n\n\
                    ## Implementation Challenges\n\
                    *   Latency in high-parameter reasoning.\n\n\
                    ## Conclusion and Future Directions\n\
                    *   Summary of research findings.\n\n\
                    ## References\n\
                    *   (Source 1) A Survey of Agentic Harnesses, arXiv (Aug 2026)";
        let outline = parse_outline(text).expect("heading-style outline should parse");
        assert_eq!(outline.len(), 5);
        assert_eq!(outline[0].title, "Introduction");
        assert!(outline[0].brief.contains("scripted NPCs"));
        assert_eq!(outline[4].title, "References");
        // The reference section keeps the low floor + reference guidance.
        assert_eq!(section_min_chars(&outline[4]), 100);
    }

    #[test]
    fn parse_outline_numbered_takes_precedence_over_headings() {
        // A numbered outline followed by stray headings must parse as the
        // numbered plan (old behavior), not pick up the trailing headings.
        let text = "## Outline\n1. Summary — a\n2. Body — b\n3. Sources — c\n\
                    ## Trailer\ncontent";
        let outline = parse_outline(text).expect("numbered outline should parse");
        assert_eq!(outline.len(), 3);
        assert_eq!(outline[2].title, "Sources");
    }

    #[test]
    fn parse_outline_heading_style_briefs_are_capped() {
        let mut text = String::from("## Outline\n## A\n");
        for i in 0..30 {
            text.push_str(&format!("* filler bullet number {i} with some length\n"));
        }
        text.push_str("## B\n## C\n");
        let outline = parse_outline(&text).expect("should parse");
        assert!(outline[0].brief.chars().count() < 260);
    }

    #[test]
    fn gather_deliverable_ok_splits_notes_and_outline() {
        let text = format!(
            "## Notes\n- [S1] Paper — arXiv — 2026 — url\n  - {}\n\n\
             ## Outline\n1. Summary — a\n2. Body — b\n3. Sources — c",
            "a concrete finding with enough substance to matter ".repeat(6)
        );
        let (outline, notes) = gather_deliverable(&text).expect("should be usable");
        assert_eq!(outline.len(), 3);
        assert!(notes.starts_with("## Notes"));
        assert!(!notes.to_lowercase().contains("## outline"));
    }

    #[test]
    fn gather_deliverable_rejects_stall_narration() {
        // Abbreviated from the real 8-21 cron gather: the model narrated
        // the plan instead of delivering it — no outline block at all.
        let text = "I am currently executing the GATHER phase of the deep \
                    research task. I am initiating four targeted searches to \
                    surface recent primary sources. My objective is to identify \
                    new architectural patterns.";
        let err = gather_deliverable(text).unwrap_err();
        assert!(err.contains("no parseable outline"), "{err}");
    }

    #[test]
    fn gather_deliverable_rejects_thin_notes() {
        let text = "## Notes\n- one line\n\n\
                    ## Outline\n1. Summary — a\n2. Body — b\n3. Sources — c";
        let err = gather_deliverable(text).unwrap_err();
        assert!(err.contains("chars of notes"), "{err}");
    }

    #[test]
    fn split_title_brief_no_separator() {
        let (t, b) = split_title_brief("Just A Title");
        assert_eq!(t, "Just A Title");
        assert!(b.is_empty());
    }

    #[test]
    fn section_prompt_marks_current_and_embeds_notes() {
        let outline = vec![
            SectionSpec { title: "Summary".into(), brief: "a".into() },
            SectionSpec { title: "Body".into(), brief: "b".into() },
            SectionSpec { title: "Sources".into(), brief: String::new() },
        ];
        let p = build_section_prompt("topic X", "deep", "NOTES-HERE", &outline, 1, &[]);
        assert!(p.contains("YOU ARE WRITING THIS ONE"));
        assert!(p.contains("NOTES-HERE"));
        assert!(p.contains("## Body"));
        assert!(p.contains("Do NOT call any tools"));
    }

    #[test]
    fn sources_section_gets_reference_guidance_and_lower_floor() {
        let outline = vec![
            SectionSpec { title: "Summary".into(), brief: String::new() },
            SectionSpec { title: "Body".into(), brief: String::new() },
            SectionSpec { title: "Sources".into(), brief: String::new() },
        ];
        let p = build_section_prompt("t", "standard", "n", &outline, 2, &[]);
        assert!(p.contains("reference list"));
        assert_eq!(section_min_chars(&outline[2]), 100);
        assert_eq!(section_min_chars(&outline[1]), 250);
    }

    #[test]
    fn gather_prompt_carries_sourcing_and_deliverable_shape() {
        let p = build_gather_prompt("agentic AI", "deep", "");
        assert!(p.contains("GATHER phase"));
        assert!(p.contains("web_search is your PRIMARY tool"));
        assert!(p.contains("## Outline"));
        assert!(p.contains("6-7 sections"));
        assert!(p.contains("Do NOT write the report itself"));
        // The {searches} placeholder must be resolved.
        assert!(!p.contains("{searches}"));
        assert!(p.contains("4 searches"));
    }

    #[test]
    fn count_sources_counts_distinct_top_level_bullets() {
        let notes = "## Notes\n- [S1] A — x — 2026 — u\n  - finding cites [S2]\n\
                     - [S2] B — y — 2026 — u\n* [S3] C — z — 2026 — u\n- [S1] A again\n";
        assert_eq!(count_sources(notes), 3);
        assert_eq!(count_sources("no bullets here"), 0);
        assert_eq!(min_sources("standard"), 5);
        assert!(min_sources("deep") > min_sources("standard"));
    }

    #[test]
    fn normalize_outline_adds_summary_and_sources_and_moves_sources_last() {
        let bare = vec![
            SectionSpec { title: "Local-First".into(), brief: String::new() },
            SectionSpec { title: "Reasoning".into(), brief: String::new() },
        ];
        let n = normalize_outline(bare);
        assert_eq!(n.first().unwrap().title, "Summary");
        assert_eq!(n.last().unwrap().title, "Sources");
        assert_eq!(n.len(), 4);

        let mid = vec![
            SectionSpec { title: "Summary".into(), brief: String::new() },
            SectionSpec { title: "References".into(), brief: String::new() },
            SectionSpec { title: "Body".into(), brief: String::new() },
        ];
        let n = normalize_outline(mid);
        assert_eq!(n.iter().map(|s| s.title.as_str()).collect::<Vec<_>>(), ["Summary", "Body", "References"]);
    }

    #[test]
    fn stray_reference_lists_are_cut_but_prose_is_kept() {
        let with_refs = "## Architecture\n\nProse about MoE [S1].\n\nReferences\n[S1] arXiv, 2026\n";
        assert_eq!(strip_stray_reference_list(with_refs), "## Architecture\n\nProse about MoE [S1].");
        let bold = "## A\n\nText.\n\n**Sources:**\n- x";
        assert_eq!(strip_stray_reference_list(bold), "## A\n\nText.");
        let heading = "## A\n\nText.\n\n### Bibliography\n- x";
        assert_eq!(strip_stray_reference_list(heading), "## A\n\nText.");
        // A title that merely contains the word is prose, not a list.
        let prose = "## Open-Source Models\n\nSources of error include drift.";
        assert_eq!(strip_stray_reference_list(prose), prose);
    }

    #[test]
    fn later_sections_see_what_earlier_ones_said_and_sources_does_not() {
        let outline = vec![
            SectionSpec { title: "Summary".into(), brief: String::new() },
            SectionSpec { title: "Body".into(), brief: String::new() },
            SectionSpec { title: "Sources".into(), brief: String::new() },
        ];
        let written = vec!["## Summary\n\nQUANTIZATION-POINT made here.".to_string()];
        let p = build_section_prompt("t", "standard", "n", &outline, 1, &written);
        assert!(p.contains("Already written"));
        assert!(p.contains("QUANTIZATION-POINT"));
        assert!(p.contains("Do not include a references"));
        let src = build_section_prompt("t", "standard", "n", &outline, 2, &written);
        assert!(!src.contains("Already written"), "the Sources section lists references, it has nothing to avoid repeating");
        let first = build_section_prompt("t", "standard", "n", &outline, 0, &[]);
        assert!(!first.contains("Already written"));
    }

    #[test]
    fn gather_prompt_asks_for_a_minimum_number_of_sources() {
        let p = build_gather_prompt("agentic AI", "standard", "");
        assert!(p.contains("at least 5 DISTINCT sources"));
        assert!(!p.contains("{min_sources}"));
    }
}
