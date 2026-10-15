// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The harness kinds a harness placement may name in `NOO_HARNESS_KIND`,
//! declared ONCE in `config/harness-kinds.json` and embedded here at compile
//! time. The node agent embeds a copy of the same file (held equal by its
//! `TestHarnessKindsTableMatchesTheShippedFile`), so adding a kind is one
//! edit to that file plus the copy, not a constant in each binary.
//!
//! The path is a literal `../../config/...` rather than
//! `concat!(env!("CARGO_MANIFEST_DIR"), ...)` so
//! `tests/test_rust_build_context_complete.py` sees it and holds the Docker
//! builder stage's COPY list to it.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::Deserialize;

const RAW: &str = include_str!("../../config/harness-kinds.json");

/// One row of the table.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // the gateway validates by name; the other fields are the node agent's
pub struct HarnessKind {
    pub kind: String,
    pub title: String,
    /// The API the harness speaks.
    pub wire: String,
    /// Node chat backend types that serve that wire (empty: none yet).
    pub wires: Vec<String>,
    /// The executable the applier installs beside the agent; `None` = no
    /// runner ships yet, and the node agent refuses the kind.
    pub runner: Option<String>,
    /// Vendor telemetry switches the runner must launch it with.
    pub telemetry_off: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Table {
    kinds: Vec<HarnessKind>,
}

static KINDS: LazyLock<Vec<HarnessKind>> = LazyLock::new(|| {
    serde_json::from_str::<Table>(RAW)
        .expect("config/harness-kinds.json is malformed")
        .kinds
});

/// Every declared kind, in declared order (`noo` first).
#[allow(dead_code)]
pub fn all() -> &'static [HarnessKind] {
    &KINDS
}

/// The kind names, in declared order.
pub fn names() -> Vec<&'static str> {
    KINDS.iter().map(|k| k.kind.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_shipped_table_parses() {
        let t: Table = serde_json::from_str(RAW).expect("config/harness-kinds.json parses");
        assert!(!t.kinds.is_empty(), "no kinds declared");
        assert_eq!(all().len(), t.kinds.len());
    }

    #[test]
    fn noo_is_first_and_has_a_runner() {
        let first = &all()[0];
        assert_eq!(first.kind, "noo");
        assert_eq!(first.runner.as_deref(), Some("noo-gateway"));
    }

    #[test]
    fn every_kind_declares_its_telemetry_switches() {
        // The map may be empty; the KEY may not be absent (serde would
        // reject the row), and a raw-JSON look makes that explicit.
        let v: serde_json::Value = serde_json::from_str(RAW).unwrap();
        for k in v["kinds"].as_array().unwrap() {
            assert!(k.get("telemetry_off").is_some_and(|t| t.is_object()), "{} has no telemetry_off object", k["kind"]);
        }
    }

    #[test]
    fn kinds_are_unique() {
        let mut seen = HashSet::new();
        for n in names() {
            assert!(!n.is_empty(), "an empty kind");
            assert!(seen.insert(n), "kind {n} declared twice");
        }
    }

    #[test]
    fn the_validation_message_lists_the_table() {
        assert_eq!(names().join(", "), "noo, claude-code, copilot, codex");
    }
}
