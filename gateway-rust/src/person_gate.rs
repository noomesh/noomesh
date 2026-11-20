// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The person gate (i1096): keys never manage keys or people.
//!
//! Every gateway route that changes WHO CAN DO WHAT (accounts, roles, org and
//! team membership, KB grants, channel links, service keys, add-on access,
//! seat and node credentials, decisions on user-management proposals) is done
//! by a person. A person is [`Origin::Person`]: a login, host-ticket or
//! browser session token, the operator-certificate token or a "View as"
//! token, for an enabled account. Anything else ([`Origin::Agent`]: a token
//! exchanged from a service key, an MCP door token, a worker-delegated or
//! add-on token, a kiosk or service identity, a call with no account) is
//! refused 403 with the machine code [`PERSON_REQUIRED`], and every refusal
//! writes a `person_required_refused` audit row naming the route and the
//! credential's kind (never the token).
//!
//! The gate is IN ADDITION to each route's own role, tier and last-admin
//! guards; it narrows who may act, it never widens.

use serde_json::json;

use crate::audit::{AuditEvent, AuditKind, Outcome};
use crate::auth::RequesterCtx;
use crate::routes::AppError;
use crate::task_guard::Origin;

/// The machine-readable code of a person-gate refusal (the 403 body's `code`).
pub(crate) const PERSON_REQUIRED: &str = "person_required";

/// The one sentence a refusal says. `what` names the action, e.g. "issuing a
/// service key".
pub(crate) fn person_required_message(what: &str) -> String {
    format!(
        "a person must do this: sign in as an admin (`noo auth login`) — {what} is not done by a key, \
         a token exchanged from one, or an agent"
    )
}

/// The rule, pure so it can be pinned: `None` = pass.
pub(crate) fn verdict(origin: &Origin, what: &str) -> Option<AppError> {
    match origin {
        Origin::Person { .. } => None,
        Origin::Agent { .. } => Some(AppError::ForbiddenCode { code: PERSON_REQUIRED, msg: person_required_message(what) }),
    }
}

/// 403 [`PERSON_REQUIRED`] unless a person made this request; every refusal is
/// audited. `r` is the request's [`RequesterCtx`] (`ctx.as_deref()` for an
/// `Option<Extension<_>>`), `what` names the action for the message and the row.
pub(crate) async fn require_person(db: &sqlx::PgPool, r: Option<&RequesterCtx>, what: &str) -> Result<(), AppError> {
    let origin = crate::task_guard::resolve_origin_of(db, r).await;
    let Some(refusal) = verdict(&origin, what) else {
        return Ok(());
    };
    let via = match &origin {
        Origin::Agent { via, .. } => via.as_str(),
        Origin::Person { .. } => "a person",
    };
    let act = r.and_then(|r| r.act.as_ref()).map(|a| a.sub.as_str());
    // The service key behind the credential, when it names one (an exchanged
    // or door token's actor is `key:<consumer>`). Never the token itself.
    let consumer = act.and_then(|a| a.strip_prefix("key:"));
    let harness = r.and_then(|r| r.harness.as_deref());
    let actor = r.map_or("anonymous", |r| r.sub.as_str());
    tracing::warn!(what, via, actor, "person_required_refused");
    crate::audit::record(
        db,
        AuditEvent::new(AuditKind::PersonRequiredRefused, actor, what)
            .outcome(Outcome::Denied)
            .details(json!({
                "what": what,
                "via": via,
                "account": origin.account(),
                "act": act,
                "consumer": consumer,
                "harness": harness,
            })),
    )
    .await;
    Err(refusal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Actor, Role};
    use crate::task_guard::origin_of_requester;

    fn ctx(sub: &str, role: Role, harness: Option<&str>, act: Option<&str>, task: Option<&str>) -> RequesterCtx {
        RequesterCtx {
            sub: sub.into(),
            scopes: role.legacy_scopes().iter().map(|s| s.to_string()).collect(),
            role,
            harness: harness.map(str::to_string),
            act: act.map(|a| Actor { sub: a.into(), iss_user: None, task: task.map(str::to_string), feature: None }),
        }
    }

    /// A RequesterCtx from the claims a real mint signs.
    fn from_claims(c: &serde_json::Value, role: Role) -> RequesterCtx {
        RequesterCtx {
            sub: c["sub"].as_str().unwrap().into(),
            scopes: vec![],
            role,
            harness: c["harness"].as_str().map(str::to_string),
            act: serde_json::from_value::<Option<Actor>>(c["act"].clone()).unwrap(),
        }
    }

    fn operator_door(role: Role) -> RequesterCtx {
        let c = crate::mcp_external::caller_claims("owner", role, &[], "operator:laptop", None, 0);
        from_claims(&c, role)
    }

    fn user_door(role: Role) -> RequesterCtx {
        let c = crate::mcp_external::caller_claims("owner", role, &[], "laptop", None, 0);
        from_claims(&c, role)
    }

    fn worker(role: Role) -> RequesterCtx {
        let p = crate::bus_principal::Principal::user("owner", role, vec![]);
        let c = crate::worker_delegation::claims(&p, "run-1", 120, "person-gate-test-secret-not-a-real-one").expect("claims");
        from_claims(&c, role)
    }

    fn identity_exchanged(role: Role) -> RequesterCtx {
        ctx("owner", role, None, Some("key:provisioner"), None)
    }

    fn is_person_required(e: &Option<AppError>) -> bool {
        matches!(e, Some(AppError::ForbiddenCode { code, msg }) if *code == PERSON_REQUIRED && msg.contains("noo auth login") && msg.starts_with("a person must do this"))
    }

    #[test]
    fn a_person_passes_and_every_agent_is_refused_person_required() {
        let person = ctx("owner", Role::Admin, None, None, None);
        assert!(verdict(&origin_of_requester(Some(&person)), "x").is_none(), "a login, session or operator-cert token");
        for (who, c) in [
            ("a token exchanged from a key", identity_exchanged(Role::Admin)),
            ("an operator-door token", operator_door(Role::Admin)),
            ("a user-door token", user_door(Role::Admin)),
            ("a worker-delegated token", worker(Role::Admin)),
            ("an add-on delegated token", ctx("owner", Role::Admin, None, Some("addon:voice"), None)),
            ("an add-on's exchanged token", ctx("addon:svc:voice", Role::User, None, None, None)),
            ("a kiosk token", ctx("kiosk:hall", Role::User, None, None, None)),
            ("a service identity", ctx("svc:grafana", Role::Admin, None, None, None)),
        ] {
            let v = verdict(&origin_of_requester(Some(&c)), "issuing a service key");
            assert!(is_person_required(&v), "{who} must be refused person_required, got {v:?}");
        }
        let none = verdict(&origin_of_requester(None), "x");
        assert!(is_person_required(&none), "a call with no account");
        // An account that is not an enabled user (resolve_origin's demotion).
        let gone = Origin::Agent { account: "gone".into(), via: "an account that is not an enabled user".into() };
        assert!(is_person_required(&verdict(&gone, "x")));
    }

    #[test]
    fn the_refusal_is_a_403_with_the_code_beside_the_message() {
        let e = AppError::ForbiddenCode { code: PERSON_REQUIRED, msg: person_required_message("issuing a service key") };
        assert_eq!(
            e.to_string(),
            "a person must do this: sign in as an admin (`noo auth login`) — issuing a service key is not done by a key, \
             a token exchanged from one, or an agent"
        );
        let r = axum::response::IntoResponse::into_response(e);
        assert_eq!(r.status(), axum::http::StatusCode::FORBIDDEN);
    }

    /// Every route the i1096 inventory found passable by a non-person
    /// credential, and the call that now gates it. The gate is the handler's
    /// first awaited call, so nothing is read or written before it (except
    /// `proposal_decide`, which reads the proposal to know whether it is a
    /// user-management one, and decides nothing before the gate).
    const GATED: &[(&str, &str, &str)] = &[
        // (a) the bypasses: a password reset, then a person's login; and keys.
        ("users.rs", "async fn user_set_password(", "require_person("),
        ("users.rs", "async fn service_key_issue(", "require_person("),
        ("users.rs", "async fn service_key_rotate(", "require_person("),
        ("users.rs", "async fn service_key_revoke(", "require_person("),
        ("users.rs", "async fn service_key_retire(", "require_person("),
        ("users.rs", "async fn service_key_revoke_and_disable(", "require_person("),
        ("users.rs", "async fn service_key_set_quota(", "require_person("),
        ("users.rs", "async fn service_key_set_context_overflow(", "require_person("),
        // (b) account role, scope, state and org.
        ("users.rs", "async fn user_create(", "require_person("),
        ("users.rs", "async fn user_set_role(", "require_person("),
        ("users.rs", "async fn user_set_scopes(", "require_person("),
        ("users.rs", "async fn user_disable(", "require_person("),
        ("users.rs", "async fn api_users_disable(", "require_person("),
        ("users.rs", "async fn user_erase(", "require_person("),
        ("users.rs", "async fn user_set_org(", "require_person("),
        ("users.rs", "async fn org_create(", "require_person("),
    ];

    fn source(file: &str) -> &'static str {
        match file {
            "users.rs" => include_str!("routes/users.rs"),
            other => panic!("no source for {other}"),
        }
    }

    #[test]
    fn every_route_that_changes_who_can_do_what_calls_the_person_gate_first() {
        assert_eq!(GATED.len(), 16, "keep the list and the count in step");
        for (file, marker, call) in GATED {
            let own = crate::test_src::own_code(source(file));
            let body = crate::test_src::fn_body(&own, marker);
            let at = body.find(call).unwrap_or_else(|| panic!("{file} {marker} does not call {call}: an agent can change who can do what"));
            assert_eq!(body.matches(call).count(), 1, "{file} {marker}: one gate");
            if *marker == "async fn proposal_decide(" {
                let decide = body.find("if body.approve {").expect("proposal_decide approves");
                assert!(at < decide, "{marker}: the gate must come before any decision");
                continue;
            }
            let first_await = body.find(".await").expect("the gate is awaited");
            assert!(
                at < first_await && !body[at..first_await].contains(';'),
                "{file} {marker}: {call} must be the first awaited call"
            );
        }
    }
}
