// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The controller's own node id — ONE answer, read the same way everywhere.
//!
//! Four sites each asked the environment for "which node am I" and no two
//! agreed on the variable: dispatch and the autonomy evaluators read
//! `NOO_CONTROLLER_NODE_ID`, the task recorder read
//! `NOO_CONTROLLER_HOSTNAME`, the telemetry path read one for the id and the
//! other for the host. Compose exports exactly one of them
//! (`NOO_CONTROLLER_HOSTNAME=${NODE_ID:-controller}`, #378), so on host8
//! the task recorder knew it was `host8` while the dispatcher, reading a
//! variable nothing sets, did not — tried the bus, waited 3 s, and ran the
//! turn in process on every controller-placed task (2026-09-22, task
//! 56d554b2). Same box, same container, two identities.
//!
//! This module is the single reader. The order is a contract: the explicit
//! id wins, then the name compose exports, then the raw `NODE_ID`; `auto`
//! and blank are "not set". No hostname fallback here — a container's
//! hostname is a container id, and an identity that changes on every
//! recreate is worse than none (see `agent_messages::controller_node`, which
//! layers that fallback on top of this for the places that need SOME name).

/// The variables consulted, in precedence order.
pub const KEYS: [&str; 3] = ["NOO_CONTROLLER_NODE_ID", "NOO_CONTROLLER_HOSTNAME", "NODE_ID"];

/// The node id as the given environment states it, or `None` when it
/// states nothing usable. Pure, so the precedence is testable.
pub fn self_node_id_from(get: impl Fn(&str) -> Option<String>) -> Option<String> {
    for k in KEYS {
        if let Some(v) = get(k) {
            let v = v.trim();
            if !v.is_empty() && v != "auto" {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// The node id from this process's environment.
pub fn self_node_id() -> Option<String> {
    self_node_id_from(|k| std::env::var(k).ok())
}

/// Is `node` this controller's own node?
pub fn is_self_node(node: &str) -> bool {
    self_node_id().as_deref() == Some(node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn the_dispatcher_recognises_the_value_compose_actually_exports() {
        // docker-compose.cluster.yml exports NOO_CONTROLLER_HOSTNAME and
        // nothing else; that alone must name the node.
        assert_eq!(self_node_id_from(env(&[("NOO_CONTROLLER_HOSTNAME", "host8")])).as_deref(), Some("host8"));
    }

    #[test]
    fn precedence_is_explicit_id_then_compose_name_then_raw_node_id() {
        let all = env(&[("NOO_CONTROLLER_NODE_ID", "a"), ("NOO_CONTROLLER_HOSTNAME", "b"), ("NODE_ID", "c")]);
        assert_eq!(self_node_id_from(all).as_deref(), Some("a"));
        let two = env(&[("NOO_CONTROLLER_HOSTNAME", "b"), ("NODE_ID", "c")]);
        assert_eq!(self_node_id_from(two).as_deref(), Some("b"));
        let one = env(&[("NODE_ID", "c")]);
        assert_eq!(self_node_id_from(one).as_deref(), Some("c"));
    }

    #[test]
    fn auto_and_blank_are_not_names() {
        assert_eq!(self_node_id_from(env(&[("NOO_CONTROLLER_HOSTNAME", "auto"), ("NODE_ID", " ")])), None);
        // A blank explicit id does not shadow a real compose name.
        assert_eq!(self_node_id_from(env(&[("NOO_CONTROLLER_NODE_ID", ""), ("NOO_CONTROLLER_HOSTNAME", "host8")])).as_deref(), Some("host8"));
        assert_eq!(self_node_id_from(env(&[])), None);
    }
}
