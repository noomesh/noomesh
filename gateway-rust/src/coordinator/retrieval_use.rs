// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Did the answer USE what a retrieval tool returned? (i1178a, half b)
//!
//! A small model can call `noo_rag_query`, get the fact back, and then answer
//! "I have no new information": a post-tool turn that is long enough to pass
//! the short-answer stall guard yet says nothing the tool returned. This
//! module is the pure rule the loops apply; no model, no I/O.
//!
//! THE RULE (one re-nudge, never a loop). Words are runs of letters and
//! digits, lowercased, at least [`MIN_TOKEN_CHARS`] (4) characters, minus a
//! small [`STOPWORDS`] set. Numbers and codes are words: "zircon-4471" is
//! `zircon` and `4471`, "14th" is `14th`.
//!
//! - the RESULT is RELEVANT when it shares at least 2 salient tokens with the
//!   user's question, or at least 1 when the question is short (3 or fewer
//!   salient tokens: "summarise anything.md" has only `anything`);
//! - the ANSWER USES the result when it contains at least 1 salient
//!   result-token that is NOT in the question (echoing the question back is
//!   not use);
//! - STALL iff a retrieval tool returned non-empty content AND the result is
//!   relevant AND the answer uses none of it AND the answer is non-empty AND
//!   no nudge has been sent yet this turn.
//!
//! There is deliberately no list of "I don't know" phrases: the test is what
//! the answer shares with the data, not how it is worded.
//!
//! Trade-off. A legitimate "the document does not say X" is NOT a stall when
//! the result is unrelated to the question (the relevance test fails). When
//! the result IS related and the answer still says "it does not say", the
//! rule fires once: that costs one extra model turn and can never produce a
//! wrong answer, because the nudge lets the model repeat a true "not in the
//! material" answer and the second answer is accepted as final.
//!
//! Cost bound: at most [`MAX_RESULT_BYTES`] of tool output and
//! [`MAX_ANSWER_BYTES`] of answer are tokenised per check.

use std::collections::BTreeSet;

/// Tools whose output is knowledge-base or memory material the user's answer
/// should draw on. A calculator, a status call or a web search is not here:
/// those never trigger the rule.
pub(super) const RETRIEVAL_TOOLS: &[&str] = &[
    "noo_rag_query",
    "noo_memory_search",
    "noo_recall_search",
    "noo_graph_semantic_search",
];

/// Most bytes of retrieval output kept for the check, across the turn.
pub(super) const MAX_RESULT_BYTES: usize = 8 * 1024;
/// Most bytes of the answer tokenised.
pub(super) const MAX_ANSWER_BYTES: usize = 16 * 1024;
/// A word shorter than this is not salient.
const MIN_TOKEN_CHARS: usize = 4;
/// A question with at most this many salient tokens is "short".
const SHORT_QUESTION_MAX_TOKENS: usize = 3;
/// Shared question/result tokens that make a result relevant.
const RELEVANT_MIN_SHARED: usize = 2;
/// The same, for a short question.
const RELEVANT_MIN_SHARED_SHORT: usize = 1;

/// The nudge: quotes nothing private.
pub(super) const RETRIEVAL_UNUSED_NUDGE: &str =
    "Your answer did not use the retrieved material shown above. Answer from the retrieved \
     material above. If it truly does not contain what was asked, say exactly what is missing.";

/// Words of 4+ characters that carry no topic, plus the labels the
/// retrieval tool's own output wraps its answer in.
const STOPWORDS: &[&str] = &[
    "about", "also", "been", "could", "does", "from", "have", "here", "into", "just", "know",
    "more", "much", "must", "only", "please", "same", "shall", "should", "some", "such", "summarise",
    "summarize", "summary", "tell", "than", "that", "their", "them", "then", "there", "these",
    "they", "this", "those", "very", "were", "what", "when", "where", "which", "while", "will",
    "with", "would", "your", "yours",
    // the shape of the tool's own output, not its content
    "hybrid", "page", "sources", "source", "strategy",
];

/// Whether `name` is a knowledge-base / memory retrieval tool.
pub(super) fn is_retrieval_tool(name: &str) -> bool {
    RETRIEVAL_TOOLS.contains(&name)
}

/// `s` cut to at most `max` bytes, on a character boundary.
fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The salient tokens of the first `max_bytes` of `text` (see the module doc).
pub(super) fn salient_tokens(text: &str, max_bytes: usize) -> BTreeSet<String> {
    cut(text, max_bytes)
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().count() >= MIN_TOKEN_CHARS)
        .map(str::to_lowercase)
        .filter(|w| !STOPWORDS.contains(&w.as_str()))
        .collect()
}

/// Append one retrieval result to the turn's buffer, never past
/// [`MAX_RESULT_BYTES`] in all.
pub(super) fn note_retrieval(buf: &mut String, output: &str) {
    let room = MAX_RESULT_BYTES.saturating_sub(buf.len());
    if room == 0 || output.trim().is_empty() {
        return;
    }
    buf.push_str(cut(output, room));
    buf.push('\n');
}

/// The result shares enough salient tokens with the question.
pub(super) fn result_is_relevant(question: &BTreeSet<String>, result: &BTreeSet<String>) -> bool {
    let shared = question.intersection(result).count();
    let need = if question.len() <= SHORT_QUESTION_MAX_TOKENS {
        RELEVANT_MIN_SHARED_SHORT
    } else {
        RELEVANT_MIN_SHARED
    };
    shared >= need
}

/// The answer holds at least one salient result-token that is not in the
/// question.
pub(super) fn answer_uses_result(
    question: &BTreeSet<String>,
    result: &BTreeSet<String>,
    answer: &BTreeSet<String>,
) -> bool {
    result.iter().any(|t| !question.contains(t) && answer.contains(t))
}

/// The whole decision: should the loop re-nudge this answer?
/// `already_nudged` is true once ANY nudge went out this turn (the rule
/// fires at most once and never after another recovery).
pub(super) fn ignores_retrieval(
    question: &str,
    retrieved: &str,
    answer: &str,
    already_nudged: bool,
) -> bool {
    if already_nudged || retrieved.trim().is_empty() || answer.trim().is_empty() {
        return false;
    }
    let result = salient_tokens(retrieved, MAX_RESULT_BYTES);
    if result.is_empty() {
        return false;
    }
    let question = salient_tokens(question, MAX_ANSWER_BYTES);
    if !result_is_relevant(&question, &result) {
        return false;
    }
    let answer = salient_tokens(answer, MAX_ANSWER_BYTES);
    !answer_uses_result(&question, &result, &answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture note a knowledge-base query returns.
    const NOTE: &str = "Kestrel ground station note: the firmware build is ZIRCON-4471, \
                        scheduled for the 14th of March.\n\nSources:\n  - [anything.md] page 1\n\n(strategy: hybrid)";
    /// The question from the rc.5 failure.
    const Q: &str = "summarise what you know from anything.md";
    /// The rc.5 non-answer.
    const NON_ANSWER: &str = "I do not have any new information to process. I have already \
                              summarized what I know from `anything.md` for you.";

    #[test]
    fn tokens_are_lowercase_four_plus_chars_minus_stopwords() {
        let t = salient_tokens("The ZIRCON-4471 build: 14th of March, and a cat.", 1024);
        let got: Vec<&str> = t.iter().map(String::as_str).collect();
        assert_eq!(got, ["14th", "4471", "build", "march", "zircon"]);
        assert!(salient_tokens("this that with from", 1024).is_empty());
    }

    #[test]
    fn tokenising_is_bounded_and_cuts_on_a_char_boundary() {
        let t = salient_tokens("alpha bravo charlie", 5);
        assert!(t.contains("alpha") && !t.contains("bravo"), "{t:?}");
        // a multi-byte char straddling the cut must not panic
        let _ = salient_tokens("ééééééé", 3);
        let mut buf = String::new();
        note_retrieval(&mut buf, &"x".repeat(MAX_RESULT_BYTES * 2));
        note_retrieval(&mut buf, "more");
        assert!(buf.len() <= MAX_RESULT_BYTES + 1, "{}", buf.len());
    }

    #[test]
    fn the_rc5_non_answer_is_a_stall() {
        assert!(ignores_retrieval(Q, NOTE, NON_ANSWER, false));
    }

    #[test]
    fn an_answer_with_a_code_or_a_date_is_not_a_stall() {
        assert!(!ignores_retrieval(Q, NOTE, "The firmware build is ZIRCON-4471.", false));
        assert!(!ignores_retrieval(Q, NOTE, "It ships on the 14th of March.", false));
    }

    #[test]
    fn an_empty_answer_is_left_to_the_existing_guard() {
        assert!(!ignores_retrieval(Q, NOTE, "", false));
        assert!(!ignores_retrieval(Q, NOTE, "   \n", false));
    }

    #[test]
    fn does_not_say_with_an_unrelated_result_is_not_a_stall() {
        let q = "Who is the project lead?";
        let a = "The document does not say who the project lead is.";
        let q_tokens = salient_tokens(q, 1024);
        let r_tokens = salient_tokens(NOTE, 1024);
        assert_eq!(q_tokens.intersection(&r_tokens).count(), 0, "fixture must share nothing");
        assert!(!ignores_retrieval(q, NOTE, a, false));
    }

    #[test]
    fn does_not_say_with_a_relevant_result_is_one_nudge_never_two() {
        let q = "What does the Kestrel note say about the firmware build?";
        let a = "The document does not say.";
        assert!(ignores_retrieval(q, NOTE, a, false));
        // after the one re-nudge the same non-answer stands
        assert!(!ignores_retrieval(q, NOTE, a, true));
        assert!(!ignores_retrieval(Q, NOTE, NON_ANSWER, true));
    }

    #[test]
    fn echoing_the_question_is_not_using_the_result() {
        let q = "What is the Kestrel firmware build?";
        let a = "The Kestrel firmware build is something I cannot determine.";
        assert!(ignores_retrieval(q, NOTE, a, false));
    }

    #[test]
    fn relevance_needs_two_shared_tokens_or_one_for_a_short_question() {
        let set = |s: &str| salient_tokens(s, 1024);
        let result = set("kestrel firmware zircon");
        // long question, one shared token: not relevant
        assert!(!result_is_relevant(&set("kestrel budget travel owner approval"), &result));
        // long question, two shared tokens: relevant
        assert!(result_is_relevant(&set("kestrel firmware travel owner approval"), &result));
        // short question (3 salient tokens), one shared token: relevant
        assert!(result_is_relevant(&set("kestrel budget owner"), &result));
        // nothing shared: never
        assert!(!result_is_relevant(&set("budget owner"), &result));
        assert!(!result_is_relevant(&set(""), &result));
    }

    #[test]
    fn only_knowledge_and_memory_tools_are_retrieval_tools() {
        for t in ["noo_rag_query", "noo_memory_search", "noo_recall_search", "noo_graph_semantic_search"] {
            assert!(is_retrieval_tool(t), "{t}");
        }
        for t in ["calculator", "noo_cluster_status", "web_search", "noo_job_list", ""] {
            assert!(!is_retrieval_tool(t), "{t}");
        }
    }

    /// No result text, no stall: a calculator-like turn never buffers anything.
    #[test]
    fn nothing_retrieved_is_never_a_stall() {
        assert!(!ignores_retrieval(Q, "", NON_ANSWER, false));
        assert!(!ignores_retrieval(Q, " \n", NON_ANSWER, false));
        let mut buf = String::new();
        note_retrieval(&mut buf, "  ");
        assert!(buf.is_empty());
    }

    #[test]
    fn the_nudge_quotes_nothing_private() {
        assert!(RETRIEVAL_UNUSED_NUDGE.contains("retrieved material above"));
        assert!(!RETRIEVAL_UNUSED_NUDGE.to_lowercase().contains("zircon"));
    }
}
