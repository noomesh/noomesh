// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Which NATS credential this process presents, and the refusal when it has
//! none.
//!
//! The bus historically had exactly one user/password, shared
//! by the gateway, the Python worker/trellion and every node-agent. Nothing
//! on the wire distinguishes them, so no subject permission can be written:
//! that one credential is a `>`/`>` credential, and holding it is holding
//! the whole bus.
//!
//! Each principal now reads its OWN pair, and that pair is the only thing it
//! presents. The shared pair (`NATS_USER`/`NATS_PASSWORD`) and its bridge
//! (`NOO_NATS_LEGACY_SHARED_CREDS`) were RETIRED: the server
//! no longer defines that user, so there is nothing to fall back to. A
//! process whose own pair is missing refuses to connect and names the verb
//! that mints it — it never quietly promotes itself to a wider credential,
//! and it never connects anonymously by accident (an empty user used to mean
//! "connect anonymously", and a server whose user list resolves to nothing
//! accepts that).
//!
//! `NOO_NATS_ALLOW_ANONYMOUS=1` remains the escape hatch for a local dev
//! server with no password at all.

/// The credential a process presents, plus which principal it is (for the
/// log line — never the password).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatsCredential {
    pub user: String,
    pub password: String,
    /// The principal role: `"gateway"` or `"node"`.
    pub source: &'static str,
}

/// The gateway's role-specific variable names.
pub const GATEWAY_USER_VAR: &str = "NATS_GATEWAY_USER";
pub const GATEWAY_PASSWORD_VAR: &str = "NATS_GATEWAY_PASSWORD";
/// A node's (and the node-hosted harness's) own pair.
pub const NODE_USER_VAR: &str = "NATS_NODE_USER";
pub const NODE_PASSWORD_VAR: &str = "NATS_NODE_PASSWORD";
/// The retired shared user. Read ONLY so the refusal can say,
/// specifically, why a still-set `NATS_USER` is ignored. Never presented.
pub const RETIRED_SHARED_USER_VAR: &str = "NATS_USER";
pub const ALLOW_ANONYMOUS_VAR: &str = "NOO_NATS_ALLOW_ANONYMOUS";

/// The remedy for a missing GATEWAY pair.
pub const GATEWAY_REMEDY: &str = "`noo cluster nats-creds rotate gateway --restart` on the \
     controller (or `noo cluster nats-users render`, which mints a missing pair)";
/// The remedy for a missing NODE pair — it has to be DELIVERED, so it is a
/// rail verb, never a controller-local render.
pub const NODE_REMEDY: &str = "`noo cluster nats-creds rotate <node>` on the controller \
     (or `noo cluster provision <node>` for a node that was never provisioned)";

/// Per-client inbox prefix. A future permission rule grants the gateway
/// `_INBOX_gw.>` and nothing else; the default `_INBOX.` cannot be scoped
/// because every principal uses it.
pub const INBOX_PREFIX: &str = "_INBOX_gw";

fn truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Resolve the gateway credential from an environment lookup.
///
/// `Ok(Some(..))` — present. `Ok(None)` — deliberately anonymous.
/// `Err(..)` — nothing set and no escape hatch: refuse to connect.
pub fn resolve(get: impl Fn(&str) -> Option<String>) -> Result<Option<NatsCredential>, String> {
    resolve_for("gateway", GATEWAY_USER_VAR, GATEWAY_PASSWORD_VAR, GATEWAY_REMEDY, get)
}

/// Resolve a node principal's credential (the node-hosted harness).
pub fn resolve_node(get: impl Fn(&str) -> Option<String>) -> Result<Option<NatsCredential>, String> {
    resolve_for("node", NODE_USER_VAR, NODE_PASSWORD_VAR, NODE_REMEDY, get)
}

pub fn resolve_for(
    role: &'static str,
    user_var: &str,
    pass_var: &str,
    remedy: &str,
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<NatsCredential>, String> {
    let read = |k: &str| get(k).map(|v| v.trim().to_string()).unwrap_or_default();

    let role_user = read(user_var);
    if !role_user.is_empty() {
        return Ok(Some(NatsCredential {
            user: role_user,
            password: read(pass_var),
            source: role,
        }));
    }

    if truthy(&read(ALLOW_ANONYMOUS_VAR)) {
        return Ok(None);
    }

    if !read(RETIRED_SHARED_USER_VAR).is_empty() {
        return Err(format!(
            "no NATS credential: {user_var}/{pass_var} are not set. \
             {RETIRED_SHARED_USER_VAR} is set, but the shared bus user was RETIRED: \
             the server no longer defines it and it is never presented. \
             Fix it: {remedy}; then recreate this process so it picks the pair up — an env \
             change does not survive a plain restart."
        ));
    }

    Err(format!(
        "no NATS credential: set {user_var}/{pass_var}. An empty user connects \
         ANONYMOUSLY and the server accepts it, which silently removes bus \
         authentication — so this is refused. Fix it: {remedy}. Set \
         {ALLOW_ANONYMOUS_VAR}=1 to connect anonymously on purpose (local dev \
         without a server password)."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Spelled out, not imported: the retired names must not come back as
    /// exported constants for a test to keep alive.
    const RETIRED_PASSWORD: &str = "NATS_PASSWORD";
    const RETIRED_BRIDGE: &str = "NOO_NATS_LEGACY_SHARED_CREDS";

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn role_pair_wins_over_shared() {
        let c = resolve(env(&[
            (GATEWAY_USER_VAR, "gateway"),
            (GATEWAY_PASSWORD_VAR, "gw-secret"),
            (RETIRED_SHARED_USER_VAR, "noo"),
            (RETIRED_PASSWORD, "fleet-secret"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(c.user, "gateway");
        assert_eq!(c.password, "gw-secret");
        assert_eq!(c.source, "gateway");
    }

    /// Before the retirement `resolve` handed the shared pair
    /// back labelled `shared`, and the bridge decided later whether to serve
    /// on it. The server no longer defines that user, so there is nothing to
    /// bridge to: the shared pair is refused whatever the retired bridge says.
    #[test]
    fn the_shared_pair_is_refused_whatever_the_retired_bridge_says() {
        for bridge in ["", "0", "1", "true"] {
            let err = resolve(env(&[
                (RETIRED_SHARED_USER_VAR, "noo"),
                (RETIRED_PASSWORD, "fleet"),
                (RETIRED_BRIDGE, bridge),
            ]))
            .unwrap_err();
            assert!(err.contains("RETIRED"), "{err}");
            assert!(err.contains(GATEWAY_USER_VAR), "{err}");
            assert!(err.contains("nats-creds rotate gateway"), "{err}");
            assert!(!err.contains(RETIRED_BRIDGE), "must not offer the retired bridge: {err}");
        }
    }

    #[test]
    fn a_node_refusal_names_the_delivering_verbs() {
        // A node's pair has to TRAVEL, so a controller-local render is not its
        // remedy — the refusal names the rail verbs.
        let err = resolve_node(env(&[(RETIRED_SHARED_USER_VAR, "noo"), (RETIRED_PASSWORD, "x")])).unwrap_err();
        assert!(err.contains("nats-creds rotate <node>"), "{err}");
        assert!(err.contains("cluster provision <node>"), "{err}");
        assert!(err.contains(NODE_USER_VAR), "{err}");
        let err = resolve_node(env(&[])).unwrap_err();
        assert!(err.contains("nats-creds rotate <node>"), "{err}");
        let c = resolve_node(env(&[(NODE_USER_VAR, "node-host3"), (NODE_PASSWORD_VAR, "p")]))
            .unwrap()
            .unwrap();
        assert_eq!((c.user.as_str(), c.source), ("node-host3", "node"));
    }

    #[test]
    fn blank_role_user_does_not_fall_through_to_the_shared_pair() {
        assert!(resolve(env(&[
            (GATEWAY_USER_VAR, "  "),
            (RETIRED_SHARED_USER_VAR, "noo"),
            (RETIRED_PASSWORD, "fleet"),
            (RETIRED_BRIDGE, "1"),
        ]))
        .is_err());
    }

    #[test]
    fn both_empty_refuses_and_names_the_variables() {
        let err = resolve(env(&[])).unwrap_err();
        assert!(err.contains(GATEWAY_USER_VAR), "{err}");
        assert!(err.contains(ALLOW_ANONYMOUS_VAR), "{err}");
        // It must point at the command that mints the pair.
        assert!(err.contains("nats-creds rotate gateway"), "{err}");
    }

    #[test]
    fn empty_string_user_is_not_a_credential() {
        assert!(resolve(env(&[(RETIRED_SHARED_USER_VAR, ""), (RETIRED_PASSWORD, "")])).is_err());
    }

    #[test]
    fn escape_hatch_allows_anonymous() {
        assert_eq!(resolve(env(&[(ALLOW_ANONYMOUS_VAR, "1")])).unwrap(), None);
        assert_eq!(resolve(env(&[(ALLOW_ANONYMOUS_VAR, "true")])).unwrap(), None);
    }

    #[test]
    fn escape_hatch_does_not_smuggle_the_shared_pair_in() {
        // Anonymous is anonymous: the retired pair is not a second spelling.
        assert_eq!(
            resolve(env(&[
                (ALLOW_ANONYMOUS_VAR, "1"),
                (RETIRED_SHARED_USER_VAR, "noo"),
                (RETIRED_PASSWORD, "fleet"),
            ]))
            .unwrap(),
            None
        );
    }

    #[test]
    fn escape_hatch_does_not_discard_a_configured_credential() {
        let c = resolve(env(&[(ALLOW_ANONYMOUS_VAR, "1"), (GATEWAY_USER_VAR, "gateway")]))
            .unwrap()
            .unwrap();
        assert_eq!(c.user, "gateway");
    }

    #[test]
    fn escape_hatch_ignores_non_truthy_values() {
        assert!(resolve(env(&[(ALLOW_ANONYMOUS_VAR, "0")])).is_err());
        assert!(resolve(env(&[(ALLOW_ANONYMOUS_VAR, "no")])).is_err());
    }

    #[test]
    fn inbox_prefix_is_gateway_scoped() {
        assert_eq!(INBOX_PREFIX, "_INBOX_gw");
        assert!(!INBOX_PREFIX.contains('.'), "a dot would create a subject hierarchy");
    }
}
