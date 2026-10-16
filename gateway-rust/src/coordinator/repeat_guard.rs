// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! One search per question per turn.
//!
//! gemma-4 12B on mcmini (2026-10-16) spent seven iterations of one turn
//! re-running `noo_rag_query` for "What do we know about trading?", "What is
//! trading?", "What is trading?" (hybrid) — every result empty, every
//! iteration re-planning from scratch. Nothing in the loop noticed. Only the
//! iteration cap could have stopped it.
//!
//! The guard keys a call on its tool name plus the CONTENT words of its text
//! argument (`query` / `question` / `q` / `prompt`), so rewording the same
//! question does not count as a new one. A tool without a text argument
//! (status polls, job ids) is never keyed: polling is legitimate. A repeat
//! is not executed; the model gets a tool result that says so and tells it
//! to answer with what it has.

use std::collections::{BTreeSet, HashMap};

use serde_json::Value;

use crate::tools::{ToolCall, ToolResult};

const TEXT_ARGS: &[&str] = &["query", "question", "q", "prompt"];

/// Words that change the phrasing of a lookup, not its subject.
const STOPWORDS: &[&str] = &[
    "a", "about", "an", "and", "any", "are", "can", "do", "does", "for", "from", "how",
    "i", "in", "info", "information", "is", "it", "know", "me", "of", "on", "or", "our",
    "please", "tell", "the", "there", "to", "us", "we", "what", "whats", "which", "who",
    "with", "you", "your",
];

#[derive(Default)]
pub(super) struct RepeatGuard {
    /// key → the iteration that first ran it.
    seen: HashMap<String, u32>,
}

impl RepeatGuard {
    /// `None`: run the call. `Some(result)`: it repeats an earlier call in
    /// this turn; hand the model this result instead of running it.
    pub(super) fn check(&mut self, call: &ToolCall, iteration: u32) -> Option<ToolResult> {
        let (key, subject) = call_key(&call.name, &call.arguments)?;
        if let Some(first) = self.seen.get(&key) {
            return Some(ToolResult {
                name: call.name.clone(),
                tool_call_id: call.id.clone(),
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Not run again: {} already looked up \"{subject}\" in this turn \
                     (step {first}); its result is above. Do not search for it again. \
                     If nothing was found, say so and answer the user's latest message \
                     from what you know.",
                    call.name
                )),
            });
        }
        self.seen.insert(key, iteration);
        None
    }
}

/// `(key, subject words)` for a call with a text argument, else `None`.
fn call_key(name: &str, args: &Value) -> Option<(String, String)> {
    let text = TEXT_ARGS.iter().find_map(|k| args.get(*k).and_then(Value::as_str))?;
    let lowered = text.to_lowercase();
    let words: Vec<&str> = lowered
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    if words.is_empty() {
        return None;
    }
    let content: BTreeSet<&str> = words.iter().copied().filter(|w| !STOPWORDS.contains(w)).collect();
    // All stopwords ("what is it"): key on the whole phrase instead.
    let subject = if content.is_empty() {
        words.join(" ")
    } else {
        content.into_iter().collect::<Vec<_>>().join(" ")
    };
    Some((format!("{name}\u{1f}{subject}"), subject))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn call(name: &str, args: Value) -> ToolCall {
        ToolCall { id: "c1".into(), name: name.into(), arguments: args }
    }

    #[test]
    fn rewording_the_same_question_is_a_repeat() {
        // The three lookups mcmini ran on 2026-10-16.
        let mut g = RepeatGuard::default();
        assert!(g.check(&call("noo_rag_query", json!({"question": "What do we know about trading?"})), 1).is_none());
        let r = g
            .check(&call("noo_rag_query", json!({"question": "What is trading?", "strategy": "hybrid"})), 4)
            .expect("reworded repeat is caught");
        assert!(!r.success);
        let msg = r.error.unwrap();
        assert!(msg.contains("\"trading\"") && msg.contains("step 1"), "{msg}");
        assert!(g.check(&call("noo_rag_query", json!({"question": "What is trading?"})), 5).is_some());
    }

    #[test]
    fn a_different_subject_or_tool_runs() {
        let mut g = RepeatGuard::default();
        assert!(g.check(&call("noo_rag_query", json!({"question": "trading"})), 1).is_none());
        assert!(g.check(&call("noo_rag_query", json!({"question": "machine learning"})), 1).is_none());
        // Same words, different tool: memory and the knowledge base are different sources.
        assert!(g.check(&call("noo_memory_search", json!({"query": "trading"})), 1).is_none());
    }

    #[test]
    fn calls_without_a_text_argument_are_never_blocked() {
        // Polling a job is legitimate.
        let mut g = RepeatGuard::default();
        for i in 1..=3 {
            assert!(g.check(&call("noo_job_status", json!({"job_id": "j1"})), i).is_none());
        }
        assert!(g.check(&call("noo_cluster_status", json!({})), 1).is_none());
        assert!(g.check(&call("noo_cluster_status", json!({})), 2).is_none());
    }

    #[test]
    fn an_all_stopword_query_keys_on_the_phrase() {
        let mut g = RepeatGuard::default();
        assert!(g.check(&call("noo_memory_search", json!({"query": "what is it"})), 1).is_none());
        assert!(g.check(&call("noo_memory_search", json!({"query": "what about you"})), 1).is_none());
        assert!(g.check(&call("noo_memory_search", json!({"query": "What is it?"})), 2).is_some());
    }
}
