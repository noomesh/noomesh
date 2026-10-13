// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Migration ledger — which Python NATS subjects a Rust route has replaced.
//!
//! ## The problem this solves
//!
//! Porting a handler to Rust does not delete the Python one. It makes it
//! *unreachable*, which looks identical to "still in use" from the Python
//! side: the module still imports, `@worker_handler` still registers, and
//! `worker_pool` still subscribes. Nothing says "this is dead now".
//!
//! the design established that by hand — grep every `@worker_handler`, grep
//! every subject literal in Rust, build a shadow table of routes and methods,
//! and diff. It took three passes and produced two wrong answers on the way
//! (a same-line-only regex hid multi-line call sites; method-blind matching
//! mis-shadowed `POST /api/snapshots/consolidate`). That analysis goes stale
//! the moment anyone ports another handler.
//!
//! A ledger replaces the analysis with a declaration. Each Rust route that
//! supersedes a Python subject says so, once, next to itself — and a preflight
//! check turns that into a live answer: *these Python handlers are still
//! registered and can now be deleted.*
//!
//! ## Why this shape
//!
//! - **No dependencies.** `const` data and `macro_rules!`. Adding `inventory`
//!   or `linkme` would buy distributed registration at the cost of link-time
//!   magic — and the Rust version of the Python footgun, where a handler in a
//!   module nothing references is silently dropped by the linker.
//! - **Composable per module.** Each route module owns a `PORTED` slice;
//!   [`all`] concatenates them. Adding a module is one line, same as
//!   `.merge(module::router())`.
//! - **Not a router.** axum already panics on duplicate `(path, method)`, so
//!   this deliberately does not wrap route registration. It records intent —
//!   the thing axum cannot know.
//!
//! ## Using it
//!
//! When porting a handler, add one entry beside the route:
//!
//! ```ignore
//! pub const PORTED: &[Ported] = &[
//!     Ported::new("POST", "/api/cluster/discover", "worker.api.cluster.discover"),
//! ];
//! ```
//!
//! Then delete the Python handler once preflight reports it superseded. The
//! entry stays: it is the record of *why* no Python exists for that path, and
//! preflight will report `already removed` from then on.

/// One Rust route that has taken over a Python NATS subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ported {
    /// HTTP method of the Rust route. Method matters: `POST /api/x` does not
    /// supersede a handler reached by `GET /api/x`, and conflating the two is
    /// exactly how the design's first pass got `snapshots.consolidate` wrong.
    pub method: &'static str,
    /// Rust route path, as registered with axum.
    pub path: &'static str,
    /// The `worker.*` subject this replaced.
    pub supersedes: &'static str,
}

impl Ported {
    pub const fn new(method: &'static str, path: &'static str, supersedes: &'static str) -> Self {
        Self { method, path, supersedes }
    }
}

/// Declare a module's ported routes.
///
/// Sugar over a `const` slice so the common case reads as data:
///
/// ```ignore
/// ported! {
///     POST "/api/cluster/discover" => "worker.api.cluster.discover",
///     GET  "/api/mesh/status"     => "worker.api.mesh.status",
/// }
/// ```
#[macro_export]
macro_rules! ported {
    ($($method:ident $path:literal => $subject:literal),* $(,)?) => {
        pub const PORTED: &[$crate::ported::Ported] = &[
            $( $crate::ported::Ported::new(stringify!($method), $path, $subject) ),*
        ];
    };
}

/// Every ported route across all modules.
///
/// Add a module here when it gains a `PORTED` slice — the same one-line
/// registration as merging its router.
pub fn all() -> Vec<Ported> {
    let mut v = Vec::new();
    v.extend_from_slice(crate::routes::cluster::PORTED);
    v.extend_from_slice(crate::routes::admin::PORTED);
    v.extend_from_slice(crate::routes::inference::PORTED);
    v.extend_from_slice(crate::routes::users::PORTED);
    v.extend_from_slice(crate::routes::settings::PORTED);
    v.extend_from_slice(crate::routes::communication::PORTED);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_entries_are_well_formed() {
        for p in all() {
            assert!(p.path.starts_with('/'), "{} must be a path", p.path);
            assert!(
                p.supersedes.starts_with("worker."),
                "{} must be a worker subject",
                p.supersedes
            );
            assert!(
                matches!(p.method, "GET" | "POST" | "PUT" | "DELETE" | "PATCH"),
                "{} is not an HTTP method",
                p.method
            );
        }
    }

    #[test]
    fn one_subject_is_claimed_by_exactly_one_route() {
        // Two routes claiming the same subject means one of them is wrong
        // about what it replaced, and the ledger would report a handler
        // deletable on the strength of the wrong port.
        let all = all();
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(
                    a.supersedes, b.supersedes,
                    "{} claimed by both {} {} and {} {}",
                    a.supersedes, a.method, a.path, b.method, b.path
                );
            }
        }
    }
}
