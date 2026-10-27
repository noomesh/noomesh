// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! What a model can do, declared ONCE in `config/model-capabilities.json`
//! and embedded here at compile time (i226 decision 3, phase C). Today a
//! row carries the model's own context ceiling, which caps the window
//! [`crate::harness_fit`] judges a harness kind against: no engine setting
//! gives a model more context than it was built for.
//!
//! A model with no row is unknown and has no ceiling: a guess never
//! refuses a placement. A number goes in the table only with the place it
//! was read (`evidence`).
//!
//! The path is a literal `../../config/...` so
//! `tests/test_rust_build_context_complete.py` holds the Docker builder
//! stage's COPY list to it.

use std::sync::LazyLock;

use serde::Deserialize;

const RAW: &str = include_str!("../../config/model-capabilities.json");

/// One row of the table.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelCapabilities {
    /// A name for the row (not matched against anything).
    #[allow(dead_code)]
    pub family: String,
    /// Globs (`*` only) over the model id, lower-cased, registry or org
    /// prefix removed: `gemma-4-12b*`, `gemma4:12b*`.
    #[serde(rename = "match")]
    pub patterns: Vec<String>,
    /// The model's own context ceiling, in tokens.
    pub max_context: Option<u64>,
    /// Where the numbers were read.
    #[allow(dead_code)]
    pub evidence: String,
}

#[derive(Deserialize)]
struct Table {
    models: Vec<ModelCapabilities>,
}

static MODELS: LazyLock<Vec<ModelCapabilities>> = LazyLock::new(|| {
    serde_json::from_str::<Table>(RAW)
        .expect("config/model-capabilities.json is malformed")
        .models
});

/// `google/gemma-4-12B-it` → `gemma-4-12b-it`; `registry.ollama.ai/library/gemma4:12b` → `gemma4:12b`.
fn normalise(model: &str) -> String {
    let m = model.trim();
    m.rsplit_once('/').map_or(m, |(_, base)| base).to_ascii_lowercase()
}

/// `*` matches any run of characters, everything else itself.
fn glob(pattern: &str, s: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = s.strip_prefix(first) else { return false };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else { return rest.is_empty() };
    for p in middle {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

/// The first row whose globs match `model`.
pub fn lookup(model: &str) -> Option<&'static ModelCapabilities> {
    let m = normalise(model);
    if m.is_empty() {
        return None;
    }
    MODELS.iter().find(|row| row.patterns.iter().any(|p| glob(p, &m)))
}

/// The model's own context ceiling, when the table declares one.
pub fn max_context(model: &str) -> Option<u64> {
    lookup(model).and_then(|r| r.max_context).filter(|n| *n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_parses_and_every_row_says_where_its_numbers_came_from() {
        assert!(!MODELS.is_empty());
        for row in MODELS.iter() {
            assert!(!row.patterns.is_empty(), "{} matches nothing", row.family);
            assert!(row.patterns.iter().all(|p| p == &p.to_ascii_lowercase() && !p.contains('/')), "{}: patterns are lower-case model ids", row.family);
            assert!(row.evidence.trim().len() > 20, "{} has no evidence", row.family);
        }
    }

    #[test]
    fn the_spellings_of_one_model_find_its_row() {
        for id in ["gemma-4-12B-it-qat-w4a16-ct", "google/gemma-4-12B-it-qat-w4a16-ct", "gemma4:12b", "gemma4:12b-it-qat", "registry.ollama.ai/library/gemma4:12b"] {
            assert_eq!(max_context(id), Some(262144), "{id}");
        }
        for id in ["gemma4:26b", "gemma-4-E2B", "qwen3:8b", "", "  "] {
            assert_eq!(max_context(id), None, "{id:?} is not declared");
        }
    }

    #[test]
    fn glob_is_star_only() {
        assert!(glob("a*", "abc") && glob("*c", "abc") && glob("a*c", "abc") && glob("abc", "abc") && glob("a*b*c", "aXbYc"));
        assert!(!glob("abc", "abcd") && !glob("a*d", "abc") && !glob("a*bc*bc", "abc") && !glob("b*", "abc"));
    }
}
