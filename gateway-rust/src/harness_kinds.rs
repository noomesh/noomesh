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
    /// The vendor executable that must be on PATH on the node (`None` for `noo`).
    pub cli: Option<String>,
    /// Env vars that keep the CLI one-shot and inside its lane.
    pub lane: BTreeMap<String, String>,
    /// How the driver invokes the CLI (`None` for `noo`).
    pub launch: Option<Launch>,
    /// Vendor telemetry switches the runner must launch it with.
    pub telemetry_off: BTreeMap<String, String>,
}

/// How the driver (`harness::driver`) invokes a foreign CLI. A value
/// starting `unverified:` is documented-but-unconfirmed, and the driver
/// refuses a kind that still carries one.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Launch {
    /// argv; `{prompt}` and `{mcp_config}` (the MCP config file the driver
    /// writes) are filled in by the driver, inside any argument.
    pub command: Vec<String>,
    /// The variable that points the CLI at the loopback translator.
    pub model_url_env: String,
    /// The variable that names the CLI's model.
    pub model_env: String,
    /// How the CLI takes an MCP server. `config-file`: the driver writes
    /// `{"mcpServers": {"noomesh": {...}}}` and passes its path as
    /// `{mcp_config}` in `command`.
    pub mcp: String,
    /// Appended to the translator's base URL (`/v1` for a CLI that appends
    /// `/chat/completions` to the URL it is given).
    #[serde(default)]
    pub model_url_suffix: String,
    /// A variable the CLI insists on before it calls a provider; the driver
    /// fills it with a placeholder, the loopback translator takes no key.
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// More variables that name a model (a CLI's background/sub-agent
    /// models); all set to the pinned model, so nothing asks for one the
    /// node does not serve.
    #[serde(default)]
    pub model_alias_envs: Vec<String>,
    /// The variable naming the CLI's config/state directory; the driver
    /// points it inside the task's own HOME.
    #[serde(default)]
    pub home_env: Option<String>,
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

/// One kind by name.
pub fn get(kind: &str) -> Option<&'static HarnessKind> {
    KINDS.iter().find(|k| k.kind == kind)
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
    fn one_runner_for_every_kind() {
        for k in all() {
            assert_eq!(k.runner.as_deref(), Some("noo-gateway"), "{} runner", k.kind);
        }
    }

    #[test]
    fn foreign_kinds_carry_a_cli_and_a_launch_recipe() {
        for k in all() {
            if k.kind == "noo" {
                assert!(k.cli.is_none() && k.launch.is_none(), "noo has no vendor CLI");
                continue;
            }
            let cli = k.cli.as_deref().unwrap_or_else(|| panic!("{} has no cli", k.kind));
            let l = k.launch.as_ref().unwrap_or_else(|| panic!("{} has no launch", k.kind));
            assert!(!l.command.is_empty(), "{} launch.command empty", k.kind);
            assert_eq!(l.command[0], cli, "{} launch.command[0] must be its cli", k.kind);
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
