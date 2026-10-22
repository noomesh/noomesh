// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Agent roles — role-specialised runs of the existing agentic loop.
//!
//! Ported from `noomesh/agents/`. Backs `/api/agent/run` and
//! `/api/agents/collaborate`.
//!
//! ## Why this is small
//!
//! The Python side looked like ~2,200 LOC (`orchestrator.py` +
//! `multi_agent.py` + `parallel_collab.py` + `factory.py`). Almost none of it
//! is role logic:
//!
//! - a **role is just a system prompt**. `AgentRole` is a five-value enum and
//!   `AgentSpec` carries `system_prompt`; the prompts below are copied
//!   verbatim so behaviour does not shift.
//! - `_classify_task` is keyword matching, ported literally including its
//!   first-match-wins ordering and researcher default.
//! - `parallel_collab.py` (958 LOC) is mostly NATS plumbing to share tokens
//!   BETWEEN PROCESSES. In one process that is `tokio::join!`.
//! - `factory.build_agent` assembles a tool registry — which
//!   `coordinator::run` already has.
//!
//! So this runs the audited loop under a role prompt rather than standing up
//! a second agent implementation beside it. Two agent loops in one binary is
//! the failure this programme keeps deleting.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRole {
    Researcher,
    Coder,
    Analyst,
    Planner,
    Reviewer,
}

impl AgentRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentRole::Researcher => "researcher",
            AgentRole::Coder => "coder",
            AgentRole::Analyst => "analyst",
            AgentRole::Planner => "planner",
            AgentRole::Reviewer => "reviewer",
        }
    }

    /// Parse a role name, case-insensitively (Python did `role.lower()`).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "researcher" => Some(AgentRole::Researcher),
            "coder" => Some(AgentRole::Coder),
            "analyst" => Some(AgentRole::Analyst),
            "planner" => Some(AgentRole::Planner),
            "reviewer" => Some(AgentRole::Reviewer),
            _ => None,
        }
    }

    pub fn all() -> [AgentRole; 5] {
        [
            AgentRole::Researcher,
            AgentRole::Coder,
            AgentRole::Analyst,
            AgentRole::Planner,
            AgentRole::Reviewer,
        ]
    }

    pub fn known_names() -> Vec<&'static str> {
        AgentRole::all().iter().map(|r| r.as_str()).collect()
    }

    /// Tool-loop budget from the Python `AgentSpec.max_tool_loops`. Carried
    /// across because it is the only thing besides the prompt that varied per
    /// role — a planner that gets five tool loops behaves differently from one
    /// that gets two.
    pub fn max_tool_loops(&self) -> u32 {
        match self {
            AgentRole::Researcher => 5,
            AgentRole::Coder => 4,
            AgentRole::Analyst => 4,
            AgentRole::Planner => 2,
            AgentRole::Reviewer => 3,
        }
    }

    /// System prompt, verbatim from `AGENT_SPECS`.
    ///
    /// Copied character-for-character, indentation included. These strings are
    /// the entire behavioural difference between roles, so "tidying" them is a
    /// behaviour change wearing the costume of a cleanup.
    pub fn system_prompt(&self) -> &'static str {
        match self {
            AgentRole::Researcher => {
                "You are a research specialist. Your role is to:\n\
        - Gather information from multiple sources\n\
        - Verify facts and cross-reference data\n\
        - Summarize findings clearly and concisely\n\
        - Identify knowledge gaps and uncertainties\n\
        Be thorough but efficient in your research."
            }
            AgentRole::Coder => {
                "You are a coding expert. Your role is to:\n\
        - Write clean, efficient, well-documented code\n\
        - Follow best practices and design patterns\n\
        - Consider edge cases and error handling\n\
        - Optimize for readability and maintainability\n\
        Focus on quality over speed."
            }
            AgentRole::Analyst => {
                "You are a data analyst. Your role is to:\n\
        - Analyze data patterns and trends\n\
        - Generate insights and recommendations\n\
        - Create clear visualizations when helpful\n\
        - Identify correlations and anomalies\n\
        Be precise and data-driven in your analysis."
            }
            AgentRole::Planner => {
                "You are a planning specialist. Your role is to:\n\
        - Break down complex tasks into steps\n\
        - Identify dependencies and ordering\n\
        - Allocate work appropriately\n\
        - Anticipate potential issues\n\
        Create actionable, structured plans."
            }
            AgentRole::Reviewer => {
                "You are a code reviewer. Your role is to:\n\
        - Identify bugs, security issues, and code smells\n\
        - Suggest improvements for clarity and performance\n\
        - Verify adherence to requirements\n\
        - Provide constructive feedback\n\
        Be thorough but respectful in reviews."
            }
        }
    }
}

/// Keyword routing, ported literally from `_classify_task`.
///
/// The ordering is load-bearing: it is if/elif in Python, so the FIRST branch
/// that matches wins. "review this code" hits `code` before `review` and
/// routes to Coder — reproducing that is the point, since changing it would
/// silently re-route live traffic. Unmatched tasks default to Researcher,
/// also as in Python.
pub fn classify(task: &str) -> AgentRole {
    let t = task.to_lowercase();
    const RESEARCH: &[&str] = &["research", "find", "search", "learn about"];
    const CODE: &[&str] = &["code", "implement", "write", "function", "class"];
    const ANALYZE: &[&str] = &["analyze", "data", "statistics", "trends"];
    const PLAN: &[&str] = &["plan", "organize", "break down", "steps"];
    const REVIEW: &[&str] = &["review", "check", "verify", "audit"];

    if RESEARCH.iter().any(|k| t.contains(k)) {
        AgentRole::Researcher
    } else if CODE.iter().any(|k| t.contains(k)) {
        AgentRole::Coder
    } else if ANALYZE.iter().any(|k| t.contains(k)) {
        AgentRole::Analyst
    } else if PLAN.iter().any(|k| t.contains(k)) {
        AgentRole::Planner
    } else if REVIEW.iter().any(|k| t.contains(k)) {
        AgentRole::Reviewer
    } else {
        AgentRole::Researcher
    }
}

/// Run one task under a role. `role` empty/None ⇒ auto-classify.
///
/// Mirrors `_OrchestratorFacade.run_agent`: an unknown role is an error
/// carrying `known_roles`, not a silent fallback — a typo that quietly ran as
/// Researcher would be indistinguishable from working.
pub async fn run_agent(
    state: &Arc<AppState>,
    prompt: &str,
    role: Option<&str>,
    conversation_id: &str,
) -> Result<Value, Value> {
    let (resolved, explicit) = match role.map(str::trim).filter(|r| !r.is_empty()) {
        Some(r) => match AgentRole::parse(r) {
            Some(role) => (role, true),
            None => {
                return Err(json!({
                    "error": format!("unknown role '{r}'"),
                    "known_roles": AgentRole::known_names(),
                }))
            }
        },
        None => (classify(prompt), false),
    };

    let result = crate::coordinator::run_with_role(
        state,
        prompt,
        conversation_id,
        "agent",
        resolved.max_tool_loops(),
        None,
        None,
        resolved.system_prompt(),
    )
    .await;

    match result {
        Ok(r) => Ok(json!({
            "response": r.response,
            // Python reported "auto" when it classified rather than obeyed.
            "role": if explicit { resolved.as_str() } else { "auto" },
        })),
        Err(e) => Err(json!({"error": e.to_string()})),
    }
}

/// Run one objective through several roles at once — as tasks. A parent task holds the objective; one child per role
/// runs it under that role's prompt, on the node holding the model, all
/// posting to the parent's thread. The parent settles when the children
/// do. With `wait_secs > 0` the call blocks until then (or the time runs
/// out) and answers in the shape the fan-out always had — `results` by
/// role — plus the task and thread ids, so a caller can keep reading.
///
/// Python defaulted to `[RESEARCHER, ANALYST]` when no roles were given,
/// and ran them in parallel; each child is its own runner, so they still
/// do. `owner` is the person the tasks run as; `None` (an internal
/// caller) runs them unattended, in process.
pub async fn collaborate(
    state: &Arc<AppState>,
    prompt: &str,
    roles: &[String],
    owner: Option<&str>,
    wait_secs: u64,
) -> Result<Value, Value> {
    let mut workflow: Vec<AgentRole> = Vec::new();
    for r in roles {
        match AgentRole::parse(r) {
            Some(role) => workflow.push(role),
            None => {
                return Err(json!({
                    "error": format!("unknown role in {roles:?}: {r}"),
                    "known_roles": AgentRole::known_names(),
                }))
            }
        }
    }
    if workflow.is_empty() {
        workflow = vec![AgentRole::Researcher, AgentRole::Analyst];
    }
    if prompt.trim().is_empty() {
        return Err(json!({"error": "prompt is required"}));
    }
    let parent = crate::tasks::create_task(&state.db, crate::tasks::NewTask {
        owner, objective: prompt, model: None, loop_budget: Some(0), parent: None, role: None, token_budget: None, created_via: None,
    })
    .await
    .map_err(|e| json!({"error": e.to_string()}))?;
    crate::tasks::start(state, &parent).await.map_err(|e| json!({"error": e.to_string()}))?;
    let mut children = Vec::new();
    for role in &workflow {
        let child = crate::tasks::create_task(&state.db, crate::tasks::NewTask {
            owner, objective: prompt, model: None, loop_budget: Some(role.max_tool_loops().max(1)), parent: Some(&parent), role: Some(role.as_str()), token_budget: None, created_via: None,
        })
        .await
        .map_err(|e| json!({"error": e.to_string()}))?;
        let started = crate::tasks::start(state, &child).await.map_err(|e| json!({"error": e.to_string()}))?;
        children.push(json!({"task_id": child.id, "role": role.as_str(), "node": started.node}));
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    let kids = loop {
        let kids = crate::tasks::children(&state.db, &parent.id).await.map_err(|e| json!({"error": e.to_string()}))?;
        if wait_secs == 0 || crate::tasks::aggregate(&kids).is_some() || tokio::time::Instant::now() >= deadline {
            break kids;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    };
    let mut results = serde_json::Map::new();
    for k in &kids {
        let text = match k.state.as_str() {
            "done" => k.result.clone().unwrap_or_default(),
            "failed" => format!("error: {}", k.error.as_deref().unwrap_or("failed")),
            other => format!("{other} (loop {} of {})", k.loops, k.loop_budget),
        };
        results.insert(k.role.clone().unwrap_or_else(|| "task".into()), json!(text));
    }
    let settled = crate::tasks::aggregate(&kids).is_some();
    Ok(json!({
        "results": results,
        "task_id": parent.id,
        "thread_id": parent.thread_id,
        "children": children,
        "settled": settled,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_roles_case_insensitively() {
        assert_eq!(AgentRole::parse("Coder"), Some(AgentRole::Coder));
        assert_eq!(AgentRole::parse("  reviewer "), Some(AgentRole::Reviewer));
        assert_eq!(AgentRole::parse("nope"), None);
    }

    #[test]
    fn known_roles_match_the_python_surface() {
        // Probed live before the port:
        //   /api/agent/run -> known_roles:
        //   ["researcher","coder","analyst","planner","reviewer"]
        assert_eq!(
            AgentRole::known_names(),
            vec!["researcher", "coder", "analyst", "planner", "reviewer"]
        );
    }

    #[test]
    fn classifier_matches_python_branch_order() {
        assert_eq!(classify("research the topic"), AgentRole::Researcher);
        assert_eq!(classify("implement a parser"), AgentRole::Coder);
        assert_eq!(classify("analyze these trends"), AgentRole::Analyst);
        assert_eq!(classify("plan the migration"), AgentRole::Planner);
        assert_eq!(classify("audit the config"), AgentRole::Reviewer);
    }

    #[test]
    fn first_match_wins_even_when_it_looks_wrong() {
        // "review this code" contains BOTH "review" and "code". Python's
        // if/elif checks code before review, so it routes to Coder. Faithful
        // beats sensible: changing it silently re-routes live traffic.
        assert_eq!(classify("review this code"), AgentRole::Coder);
        // Likewise "find" precedes everything, so a search-flavoured coding
        // request is a Researcher.
        assert_eq!(classify("find and implement a fix"), AgentRole::Researcher);
    }

    #[test]
    fn unmatched_defaults_to_researcher() {
        assert_eq!(classify("hello there"), AgentRole::Researcher);
        assert_eq!(classify(""), AgentRole::Researcher);
    }

    #[test]
    fn tool_loop_budgets_are_per_role() {
        // The only per-role setting besides the prompt; a planner with five
        // loops is not the planner these specs describe.
        assert_eq!(AgentRole::Planner.max_tool_loops(), 2);
        assert_eq!(AgentRole::Researcher.max_tool_loops(), 5);
        assert_eq!(AgentRole::Reviewer.max_tool_loops(), 3);
    }

    #[test]
    fn system_prompts_are_distinct_and_non_empty() {
        let mut seen = std::collections::HashSet::new();
        for r in AgentRole::all() {
            let p = r.system_prompt();
            assert!(!p.is_empty());
            assert!(seen.insert(p), "duplicate system prompt for {}", r.as_str());
        }
    }
}
