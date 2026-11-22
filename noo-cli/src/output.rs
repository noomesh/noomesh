// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Output + exit-code contract for native commands.
//!
//! Exit codes are part of the agent API — scripts branch on them instead of
//! parsing prose. Keep in sync with the table in main.rs and NOO_CLI.md.

#[derive(Clone, Copy)]
#[allow(dead_code)] // Ok/Generic document the full contract even before a handler uses them
pub enum ExitCode {
    Ok = 0,
    Generic = 1,
    Usage = 2,
    GatewayUnreachable = 3,
    AuthFailed = 4,
    RemoteError = 5,
    /// A run that stopped for a person: a decision it will not take for them
    /// (trust, a licence, consent, a reserve), or a step only they can do.
    /// What to run is printed. Not an error: the work so far stands.
    NeedsDecision = 6,
}

/// Print an error (JSON on stderr in json mode, human text otherwise) and exit.
pub fn fail(json: bool, code: ExitCode, kind: &str, msg: &str, hint: Option<&str>) -> ! {
    if json {
        let mut obj = serde_json::json!({ "error": msg, "code": kind });
        if let Some(h) = hint {
            obj["hint"] = serde_json::Value::String(h.to_string());
        }
        eprintln!("{obj}");
    } else {
        crate::ui::failed(msg, hint);
    }
    crate::ui::pager_finish();
    std::process::exit(code as i32);
}

/// One `next` step in --json output: `{"kind": "command", "command": "<one
/// shell-quoted line>"}`, with `"nodes": [...]` only when the command targets
/// specific nodes. Every `next` field is an array of these (`[]` when there
/// is nothing to do), built here so a later field is added in one place.
pub(crate) fn next_cmd(cmd: &str, nodes: &[&str]) -> serde_json::Value {
    let mut o = serde_json::json!({ "kind": "command", "command": cmd });
    if !nodes.is_empty() {
        o["nodes"] = serde_json::json!(nodes);
    }
    o
}

#[cfg(test)]
mod next_cmd_tests {
    use super::next_cmd;

    /// The `next` object's shape: kind + one command string, nodes only
    /// when named.
    #[test]
    fn next_cmd_is_a_command_object_with_nodes_only_when_named() {
        assert_eq!(next_cmd("noo health", &[]), serde_json::json!({ "kind": "command", "command": "noo health" }));
        assert_eq!(
            next_cmd("noo cluster verify node_a --wait", &["node_a"]),
            serde_json::json!({ "kind": "command", "command": "noo cluster verify node_a --wait", "nodes": ["node_a"] })
        );
    }
}
