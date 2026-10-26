// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Who may reach a handler: the role extractors.
//!
//! A handler that is for operators (or admins) names that in its signature:
//!
//! ```ignore
//! async fn node_bench(Operator(who): Operator, ...) -> ... { who.sub ... }
//! ```
//!
//! The check runs before the handler body, so a new route that takes the
//! extractor cannot forget it, and a reader of the signature sees the policy.
//! There used to be three helpers (`require_operator` in two files,
//! `operator_read_guard`) with opposite answers for a call that carries no
//! user; here the answer for that call is chosen at the route, by name:
//!
//! | extractor | admits | a call with NO user context (`ctx == None`) |
//! |---|---|---|
//! | [`Operator`] | role >= Operator | refused |
//! | [`Admin`] | role >= Admin | refused |
//! | [`OperatorOrInternal`] | role >= Operator | admitted |
//!
//! These run AFTER the auth middleware: they never authenticate. A missing or
//! invalid credential is answered 401 before the handler is reached; what is
//! decided here is a 403 for a credential that is valid but too low.
//! `auth::USER_READ_PATHS` and the tier allow-list remain the path-level gate;
//! this is the second lock behind it, held at the handler.
//!
//! The decisions are the pure functions [`operator_ok`], [`admin_ok`] and
//! [`operator_or_internal_ok`], so a branch inside a handler (an operator sees
//! more fields) can ask the same question without a refusal.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::auth::{RequesterCtx, Role};
use crate::routes::AppError;

/// A user context with role >= Operator.
pub(crate) fn operator_ok(ctx: Option<&RequesterCtx>) -> bool {
    ctx.is_some_and(|r| r.role >= Role::Operator)
}

/// A user context with role >= Admin.
pub(crate) fn admin_ok(ctx: Option<&RequesterCtx>) -> bool {
    ctx.is_some_and(|r| r.role >= Role::Admin)
}

/// role >= Operator, or no user context at all (see [`OperatorOrInternal`]).
pub(crate) fn operator_or_internal_ok(ctx: Option<&RequesterCtx>) -> bool {
    ctx.is_none_or(|r| r.role >= Role::Operator)
}

fn ctx_of(parts: &Parts) -> Option<RequesterCtx> {
    parts.extensions.get::<RequesterCtx>().cloned()
}

/// A logged-in user of role Operator or above. A call with no user context
/// (cluster HMAC, node token, service key) is REFUSED: the action must name a
/// person. 403 `operator role required (log in as an Operator or above)`.
#[derive(Debug, Clone)]
pub struct Operator(pub RequesterCtx);

/// A logged-in user of role Admin. A call with no user context is REFUSED.
/// 403 `admin role required (log in as an Admin)`.
#[derive(Debug, Clone)]
pub struct Admin(pub RequesterCtx);

/// role >= Operator, OR a call with no user context at all.
///
/// This is the policy the installation-wide READ routes have always had
/// (`operator_read_guard`): the user tier is kept off them, and the stack's own
/// callers pass. "No user context" means the auth layer admitted the call
/// without attaching a [`RequesterCtx`] (one is attached only for a user JWT, in
/// `auth.rs`), so the callers are: the controller's cluster
/// HMAC (`ClusterKind::Internal`: the CLI on the controller host, the
/// coordinator agent, the gateway's own services), a node's HMAC/agent token
/// on the few paths `node_route_allowed` lets a node reach, and a service key
/// (`svc:*`). They are infrastructure that already holds the fleet secret or a
/// service grant, and a read of installation state does not widen what they can
/// do. Do NOT use this on a route that CHANGES state or must name a person:
/// use [`Operator`].
///
/// `.0` is the user context when there is one (to log the actor), else `None`.
#[derive(Debug, Clone)]
pub struct OperatorOrInternal(pub Option<RequesterCtx>);

impl OperatorOrInternal {
    /// The name to record for the caller: the login, or `internal` (e.g.
    /// `"cluster-cli"`) for a call with no user context.
    pub(crate) fn actor(&self, internal: &str) -> String {
        self.0.as_ref().map_or_else(|| internal.to_string(), |r| r.sub.clone())
    }
}

impl Operator {
    /// The login, e.g. `alice` or `alice/laptop`.
    pub(crate) fn sub(&self) -> &str {
        &self.0.sub
    }
}

impl Admin {
    pub(crate) fn sub(&self) -> &str {
        &self.0.sub
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Operator {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match ctx_of(parts) {
            Some(r) if operator_ok(Some(&r)) => Ok(Operator(r)),
            _ => Err(AppError::Forbidden("operator role required (log in as an Operator or above)".into())),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Admin {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match ctx_of(parts) {
            Some(r) if admin_ok(Some(&r)) => Ok(Admin(r)),
            _ => Err(AppError::Forbidden("admin role required (log in as an Admin)".into())),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for OperatorOrInternal {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ctx = ctx_of(parts);
        if operator_or_internal_ok(ctx.as_ref()) {
            // i241: the None arm is the one a route may not need. Make every
            // admission without a user subject findable, by one stable event
            // name, so a route can be tightened on evidence.
            if ctx.is_none() {
                tracing::info!(
                    target: "security",
                    method = %parts.method,
                    path = %parts.uri.path(),
                    "authz_no_user_admitted"
                );
            }
            Ok(OperatorOrInternal(ctx))
        } else {
            Err(AppError::Forbidden("operator role required".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Request;
    use axum::http::StatusCode;
    use axum::middleware::Next;
    use axum::response::Response;
    use axum::routing::get;
    use axum::Router;

    fn ctx(role: Role) -> RequesterCtx {
        RequesterCtx { sub: "alice".into(), scopes: vec!["read".into()], role, harness: None, act: None }
    }

    /// The whole table: (role or none) x (extractor) -> admitted.
    #[test]
    fn the_policies_differ_only_where_the_table_says() {
        let user = ctx(Role::User);
        let op = ctx(Role::Operator);
        let admin = ctx(Role::Admin);
        // Operator
        assert!(!operator_ok(None) && !operator_ok(Some(&user)) && operator_ok(Some(&op)) && operator_ok(Some(&admin)));
        // Admin
        assert!(!admin_ok(None) && !admin_ok(Some(&user)) && !admin_ok(Some(&op)) && admin_ok(Some(&admin)));
        // OperatorOrInternal: only None differs from Operator
        assert!(operator_or_internal_ok(None) && !operator_or_internal_ok(Some(&user)));
        assert!(operator_or_internal_ok(Some(&op)) && operator_or_internal_ok(Some(&admin)));
    }

    /// Stand-in for the auth layer: `x-test-role: none|user|operator|admin`.
    async fn fake_auth(mut req: Request, next: Next) -> Response {
        let role = req.headers().get("x-test-role").and_then(|v| v.to_str().ok()).unwrap_or("none").to_string();
        let role = match role.as_str() {
            "user" => Some(Role::User),
            "operator" => Some(Role::Operator),
            "admin" => Some(Role::Admin),
            _ => None,
        };
        if let Some(role) = role {
            req.extensions_mut().insert(ctx(role));
        }
        next.run(req).await
    }

    /// Through a real router and a real socket (the extractors run in axum's
    /// request path, not called by hand): a `viewer`-tier (User) account gets
    /// 403 from every extractor, and a no-context call is refused by
    /// `Operator`/`Admin` and admitted by `OperatorOrInternal`.
    #[tokio::test]
    async fn extractors_answer_403_through_a_router() {
        // Paths held in constants: these are test-only mounts, not gateway
        // routes, and the OpenAPI drift scan reads literal `.route("...")`.
        const OP: &str = "/operator";
        const ADM: &str = "/admin";
        const INT: &str = "/internal";
        let app = Router::new()
            .route(OP, get(|_: Operator| async { "ok" }))
            .route(ADM, get(|_: Admin| async { "ok" }))
            .route(INT, get(|_: OperatorOrInternal| async { "ok" }))
            .layer(axum::middleware::from_fn(fake_auth));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let status = |path: &'static str, role: &'static str| {
            let client = client.clone();
            async move {
                client.get(format!("http://{addr}/{path}")).header("x-test-role", role).send().await.unwrap().status()
            }
        };
        // (path, role) -> status
        let table: [(&str, &str, StatusCode); 12] = [
            ("operator", "user", StatusCode::FORBIDDEN),
            ("operator", "none", StatusCode::FORBIDDEN),
            ("operator", "operator", StatusCode::OK),
            ("operator", "admin", StatusCode::OK),
            ("admin", "user", StatusCode::FORBIDDEN),
            ("admin", "none", StatusCode::FORBIDDEN),
            ("admin", "operator", StatusCode::FORBIDDEN),
            ("admin", "admin", StatusCode::OK),
            ("internal", "user", StatusCode::FORBIDDEN),
            ("internal", "none", StatusCode::OK),
            ("internal", "operator", StatusCode::OK),
            ("internal", "admin", StatusCode::OK),
        ];
        for (path, role, want) in table {
            assert_eq!(status(path, role).await, want, "GET /{path} as {role}");
        }
    }
}
