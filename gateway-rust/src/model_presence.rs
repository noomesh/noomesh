// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Does a node's model server actually HOLD the model it is placed for?
//!
//!
//! `running_backends` says the `ollama` container runs; it says nothing about
//! its weights. On 2026-10-03 host9 read `ollama harrier  ACTUAL Running`
//! while its Ollama held only llama3.2:1b and gemma3:1b: every embed 404'd and
//! the gateway kept offering the node on every resolution. The node-agent now
//! reports `model_presence` on each heartbeat —
//! `{"ollama": {"model": "harrier", "role": "embed", "present": false,
//! "import_only": true}}` — and this module is the ONE place that reads it.
//!
//! ## Failure semantics
//!
//! Only an explicit `present: false` is a negative. A node whose record has no
//! `model_presence` (an agent that predates the field), no entry for the
//! backend, or an entry without a boolean `present` is UNKNOWN, and unknown
//! changes nothing: the node stays a candidate, the placement keeps reading as
//! the container-level answer. The heartbeat REPLACES the field on every beat
//! (and drops it when the beat omits it), so a node rolled back to an older
//! agent does not keep a stale negative that would cut it off for good.

use serde_json::Value;

/// Every model entry the node reports for `backend`.
///
/// One ollama may host several role placements (chat + embed): the node keys
/// the PRIMARY (chat, else first) entry by the backend name, exactly as before,
/// and each further role as `<backend>#<role>` (`ollama#embed`). A node with a
/// single placement per backend reports only the bare key, so this is a strict
/// superset of the old single-entry read.
fn entries<'a>(node: &'a Value, backend: &'a str) -> impl Iterator<Item = &'a Value> {
    node.get("model_presence")
        .and_then(|m| m.as_object())
        .into_iter()
        .flat_map(|m| m.iter())
        .filter(move |(k, _)| {
            k.as_str() == backend
                || k.strip_prefix(backend).is_some_and(|rest| rest.starts_with('#'))
        })
        .map(|(_, v)| v)
}

/// True when the node REPORTS that any of `backend`'s placed models is absent.
pub fn backend_model_missing(node: &Value, backend: &str) -> bool {
    entries(node, backend).any(|e| e["present"].as_bool() == Some(false))
}

/// The first absent-model entry the node reports for `backend`, if any.
pub fn missing_entry<'a>(node: &'a Value, backend: &'a str) -> Option<&'a Value> {
    entries(node, backend).find(|e| e["present"].as_bool() == Some(false))
}

/// True only when the node reports a backend serving `role`
/// (chat | embed | rerank) whose model is absent. A role the node does not
/// report on is not missing, it is unknown.
pub fn role_model_missing(node: &Value, role: &str) -> bool {
    let Some(map) = node.get("model_presence").and_then(|v| v.as_object()) else {
        return false;
    };
    map.values().any(|e| {
        let r = match e["role"].as_str() {
            Some("") | None => "chat",
            Some(r) => r,
        };
        r == role && e["present"].as_bool() == Some(false)
    })
}

/// The model the node reports for `role` (the role=embed placement's
/// model for `embed`), or None when it does not report one.
pub fn role_model(node: &Value, role: &str) -> Option<String> {
    let map = node.get("model_presence")?.as_object()?;
    map.values().find_map(|e| {
        let r = match e["role"].as_str() {
            Some("") | None => "chat",
            Some(r) => r,
        };
        (r == role).then(|| e["model"].as_str().map(str::to_string)).flatten().filter(|m| !m.is_empty())
    })
}

/// `role_model` against the node's record in the `mesh_nodes` KV; None when
/// unknown (unreadable record, older agent that reports nothing).
pub async fn node_role_model(state: &crate::state::AppState, node_id: &str, role: &str) -> Option<String> {
    let kv = state.js.get_key_value("mesh_nodes").await.ok()?;
    let entry = kv.get(node_id).await.ok()??;
    serde_json::from_slice::<Value>(&entry).ok().and_then(|n| role_model(&n, role))
}

/// `role_model_missing` against the node's record in the `mesh_nodes` KV.
/// An unreadable record is unknown (false): not being able to look is not a
/// reason to drop a candidate.
pub async fn node_role_model_missing(state: &crate::state::AppState, node_id: &str, role: &str) -> bool {
    let Ok(kv) = state.js.get_key_value("mesh_nodes").await else { return false };
    let Ok(Some(entry)) = kv.get(node_id).await else { return false };
    serde_json::from_slice::<Value>(&entry)
        .map(|n| role_model_missing(&n, role))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// host9, 2026-10-03: container up, model absent.
    fn host9() -> Value {
        json!({"id": "host9", "status": "online",
               "running_backends": {"ollama": "harrier"},
               "model_presence": {"ollama": {"model": "harrier", "role": "embed", "present": false, "import_only": true}}})
    }

    #[test]
    fn a_second_roles_entry_under_backend_hash_role_is_read_for_the_backend() {
        let n = json!({"model_presence": {
            "ollama": {"model": "gemma4:26b-a4b-it-qat", "role": "chat", "present": true},
            "ollama#embed": {"model": "harrier", "role": "embed", "present": false, "import_only": true}}});
        assert!(backend_model_missing(&n, "ollama"), "the embed role's absent model is the backend's problem too");
        assert!(role_model_missing(&n, "embed") && !role_model_missing(&n, "chat"));
        assert_eq!(role_model(&n, "embed").as_deref(), Some("harrier"));
        assert_eq!(role_model(&n, "chat").as_deref(), Some("gemma4:26b-a4b-it-qat"));
        assert_eq!(missing_entry(&n, "ollama").unwrap()["model"], "harrier");
        assert!(!backend_model_missing(&n, "ollamax"), "a prefix of another backend's name is not this backend");
    }

    #[test]
    fn role_model_reads_the_placements_model_for_its_role() {
        let n = json!({"model_presence": {"ollama": {"model": "harrier", "role": "embed", "present": true}}});
        assert_eq!(role_model(&n, "embed").as_deref(), Some("harrier"));
        assert_eq!(role_model(&n, "chat"), None);
        assert_eq!(role_model(&json!({}), "embed"), None);
    }

    #[test]
    fn container_up_model_absent_is_missing_for_its_role_only() {
        let n = host9();
        assert!(backend_model_missing(&n, "ollama"));
        assert!(role_model_missing(&n, "embed"));
        assert!(!role_model_missing(&n, "chat"), "the embed placement says nothing about chat");
        assert!(!backend_model_missing(&n, "vllm"));
    }

    #[test]
    fn a_held_model_is_not_missing() {
        let n = json!({"model_presence": {"ollama": {"model": "harrier", "role": "embed", "present": true}}});
        assert!(!backend_model_missing(&n, "ollama"));
        assert!(!role_model_missing(&n, "embed"));
    }

    #[test]
    fn an_old_agent_that_reports_nothing_is_unknown_not_missing() {
        let old = json!({"id": "old", "running_backends": {"ollama": "harrier"}});
        assert!(!backend_model_missing(&old, "ollama"));
        assert!(!role_model_missing(&old, "embed"));
        for odd in [json!({"model_presence": null}), json!({"model_presence": {}}),
                    json!({"model_presence": {"ollama": {"model": "x"}}}),
                    json!({"model_presence": {"ollama": {"present": "no"}}})] {
            assert!(!backend_model_missing(&odd, "ollama"), "{odd}");
            assert!(!role_model_missing(&odd, "chat"), "{odd}");
        }
    }

    #[test]
    fn an_entry_with_no_role_is_a_chat_placement() {
        let n = json!({"model_presence": {"ollama": {"model": "m", "present": false}}});
        assert!(role_model_missing(&n, "chat"));
        assert!(!role_model_missing(&n, "embed"));
    }
}
