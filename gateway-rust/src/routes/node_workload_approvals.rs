// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The operator's signed node-workload approval set for one node (i596
//! slice 2).
//!
//! ```text
//! PUT /api/cluster/nodes/{node_id}/workload-approvals   {"doc": "<b64>", "sig": "<b64>"}
//! GET /api/cluster/nodes/{node_id}/workload-approvals
//! ```
//!
//! `doc` is the exact bytes of
//! `{"kind":"noomesh.node-workload-approvals/v1","node":…,"generation":N,
//! "issued_at":…,"approvals":[{"addon","digest"}]}`, and `sig` is the fleet
//! signing key's signature over them (ECDSA P-384 over SHA-256, DER: the
//! scheme of a model set). The operator's CLI signs; this gateway never holds
//! that key's private half and does not verify either: its PKI view
//! (docker-compose.cluster.yml) carries no `signing.pub`, and a gateway check
//! would not be one the node can rely on anyway. The NODE verifies, over the
//! exact bytes, with its own pinned `signing.pub`
//! (node-agent-go/internal/nodepolicy/controller.go).
//!
//! What the gateway does check is that the set is one the node would accept
//! in shape (the same rules, so a typo is refused here rather than at every
//! node silently), that it is bound to the node in the path, an enrolled one,
//! and that its generation RISES: a lower one is refused, the same one is an
//! idempotent 200 only with identical bytes. Each refusal is its own code.
//! Then it stores the bytes, writes an audit row (node, generation, entry
//! count and the document's SHA-256, never the document), and nudges the node
//! to reconcile. desired-config carries the stored pair as
//! `workload_approvals: {doc, sig}`, and leaves the key out when none is
//! stored.

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::audit::{AuditEvent, AuditKind};
use crate::repo::node_workload_approvals::{self as repo, StoredSet};
use crate::state::AppState;

/// The document's `kind`: domain separation from every other document the
/// fleet key signs. The agent's `nodepolicy.ControllerSetKind`.
pub const SET_KIND: &str = "noomesh.node-workload-approvals/v1";

/// The largest request body read. Base64 of the largest document plus a
/// signature fits well inside it.
pub const MAX_BODY_BYTES: usize = 128 << 10;
/// The largest document (decoded). A set of a few hundred entries is a few
/// tens of KiB; one past this is a mistake, not a set.
pub const MAX_DOC_BYTES: usize = 64 << 10;
/// The largest signature (decoded). A DER P-384 ECDSA signature is ~104 bytes.
pub const MAX_SIG_BYTES: usize = 512;

/// The refusal codes, one per check.
pub mod code {
    pub const TOO_LARGE: &str = "too_large";
    pub const BAD_BODY: &str = "bad_body";
    pub const BAD_BASE64: &str = "bad_base64";
    pub const DOC_INVALID: &str = "doc_invalid";
    pub const WRONG_KIND: &str = "wrong_kind";
    pub const NODE_MISMATCH: &str = "node_mismatch";
    pub const BAD_GENERATION: &str = "bad_generation";
    pub const BAD_ISSUED_AT: &str = "bad_issued_at";
    pub const BAD_ADDON: &str = "bad_addon";
    pub const BAD_DIGEST: &str = "bad_digest";
    pub const DUPLICATE_ENTRY: &str = "duplicate_entry";
    pub const GENERATION_ROLLBACK: &str = "generation_rollback";
    pub const GENERATION_CONFLICT: &str = "generation_conflict";
    pub const UNKNOWN_NODE: &str = "unknown_node";
    pub const RACED: &str = "raced";
}

/// The PUT body: the document and its signature, each standard padded base64.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    doc: String,
    sig: String,
}

/// The signed document, read strictly (the agent's `ControllerSet`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Doc {
    kind: String,
    node: String,
    generation: i64,
    issued_at: String,
    approvals: Vec<Entry>,
}

/// One approval: an add-on and one exact image digest.
#[derive(PartialEq, Eq, Hash, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    addon: String,
    digest: String,
}

/// A refusal: its status, its code and what was wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub status: StatusCode,
    pub code: &'static str,
    pub detail: String,
}

fn refuse(status: StatusCode, code: &'static str, detail: impl Into<String>) -> Refused {
    Refused { status, code, detail: detail.into() }
}

/// A set that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub generation: i64,
    pub doc: Vec<u8>,
    pub sig: Vec<u8>,
    pub entries: usize,
    /// Lower-case hex SHA-256 of the document's bytes: what the agent
    /// reports as `set_sha256` once it holds this set.
    pub doc_sha256: String,
}

/// What a PUT that passed every check does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A newer generation: store it.
    Store(Accepted),
    /// The stored generation with the stored bytes: nothing to write.
    Unchanged(Accepted),
}

/// One strict JSON value of `T`: no unknown field (the type says so), nothing
/// after it.
fn strict<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let v = T::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|_| "data after the JSON value".to_string())?;
    Ok(v)
}

fn b64_decode(field: &str, s: &str) -> Result<Vec<u8>, Refused> {
    match base64::engine::general_purpose::STANDARD.decode(s) {
        Ok(b) if !b.is_empty() => Ok(b),
        _ => Err(refuse(StatusCode::BAD_REQUEST, code::BAD_BASE64, format!("{field} is not non-empty standard base64"))),
    }
}

/// The add-on name an entry may carry: the gateway's add-on name rule AND
/// the agent's (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`, no `_`, no trailing
/// `-`), so a set the gateway stores is never one every node refuses whole.
pub fn entry_addon_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let agent_ok = !b.is_empty()
        && b.len() <= 63
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-';
    crate::addon_registry::name_ok(s) && agent_ok
}

/// `sha256:` and 64 lower-case hex digits: one exact image digest.
pub fn digest_ok(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
}

/// Judge a PUT for `path_node` against the set stored for it (`(generation,
/// doc bytes)`), in the agent's order: the size, the body, base64, the
/// document's shape, kind, node, generation, issued_at, every entry, no
/// duplicate; then the generation against the stored one. The first refusal
/// wins. Pure: no database, no clock.
pub fn validate_put(path_node: &str, stored: Option<(i64, &[u8])>, body: &[u8]) -> Result<Verdict, Refused> {
    if body.len() > MAX_BODY_BYTES {
        return Err(refuse(StatusCode::PAYLOAD_TOO_LARGE, code::TOO_LARGE, format!("the body is over {MAX_BODY_BYTES} bytes")));
    }
    let b: Body = strict(body).map_err(|e| refuse(StatusCode::BAD_REQUEST, code::BAD_BODY, format!("the body must be exactly {{doc, sig}}: {e}")))?;
    let doc = b64_decode("doc", &b.doc)?;
    let sig = b64_decode("sig", &b.sig)?;
    if doc.len() > MAX_DOC_BYTES {
        return Err(refuse(StatusCode::PAYLOAD_TOO_LARGE, code::TOO_LARGE, format!("the document is over {MAX_DOC_BYTES} bytes")));
    }
    if sig.len() > MAX_SIG_BYTES {
        return Err(refuse(StatusCode::PAYLOAD_TOO_LARGE, code::TOO_LARGE, format!("the signature is over {MAX_SIG_BYTES} bytes")));
    }
    let d: Doc = strict(&doc).map_err(|e| refuse(StatusCode::BAD_REQUEST, code::DOC_INVALID, format!("the document is not one strict approval set: {e}")))?;
    if d.kind != SET_KIND {
        return Err(refuse(StatusCode::BAD_REQUEST, code::WRONG_KIND, format!("kind is {:?}, not {SET_KIND}", d.kind)));
    }
    if d.node != path_node {
        return Err(refuse(StatusCode::BAD_REQUEST, code::NODE_MISMATCH, format!("the set is bound to {:?}, not {path_node:?}", d.node)));
    }
    if d.generation < 1 {
        return Err(refuse(StatusCode::BAD_REQUEST, code::BAD_GENERATION, format!("generation {} is below 1", d.generation)));
    }
    if chrono::DateTime::parse_from_rfc3339(&d.issued_at).is_err() {
        return Err(refuse(StatusCode::BAD_REQUEST, code::BAD_ISSUED_AT, format!("issued_at {:?} is not an RFC 3339 time", d.issued_at)));
    }
    let mut seen = HashSet::new();
    for e in &d.approvals {
        if !entry_addon_ok(&e.addon) {
            return Err(refuse(StatusCode::BAD_REQUEST, code::BAD_ADDON, format!("{:?} is not an add-on name a node accepts", e.addon)));
        }
        if !digest_ok(&e.digest) {
            return Err(refuse(StatusCode::BAD_REQUEST, code::BAD_DIGEST, format!("{:?} is not sha256:<64 lower-case hex>", e.digest)));
        }
        if !seen.insert(e) {
            return Err(refuse(StatusCode::BAD_REQUEST, code::DUPLICATE_ENTRY, format!("{} at {} is named twice", e.addon, e.digest)));
        }
    }
    let accepted = Accepted {
        generation: d.generation,
        entries: d.approvals.len(),
        doc_sha256: hex::encode(Sha256::digest(&doc)),
        doc,
        sig,
    };
    match stored {
        Some((g, _)) if accepted.generation < g => Err(refuse(
            StatusCode::CONFLICT,
            code::GENERATION_ROLLBACK,
            format!("generation {} is below the stored {g}: sign generation {} or above", accepted.generation, g + 1),
        )),
        Some((g, held)) if accepted.generation == g => {
            if held == accepted.doc.as_slice() {
                Ok(Verdict::Unchanged(accepted))
            } else {
                Err(refuse(
                    StatusCode::CONFLICT,
                    code::GENERATION_CONFLICT,
                    format!("generation {g} is stored with other bytes: sign generation {}", g + 1),
                ))
            }
        }
        _ => Ok(Verdict::Store(accepted)),
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// desired-config's `workload_approvals` for a stored set: `{doc, sig}`, the
/// exact stored bytes as base64. `None` when nothing is stored, so the key is
/// left OUT (an absent key changes nothing on the node); never `null`.
pub fn desired_field(stored: Option<&StoredSet>) -> Option<Value> {
    stored.map(|s| json!({"doc": b64(&s.doc), "sig": b64(&s.sig)}))
}

/// desired-config's `workload_approvals` for `node_id`, or `None` to leave the
/// key out: nothing stored, or the read failed (logged). Either way the node
/// keeps the set it holds.
pub async fn desired_for(state: &AppState, node_id: &str) -> Option<Value> {
    match repo::get(&state.db, node_id).await {
        Ok(s) => desired_field(s.as_ref()),
        Err(e) => {
            tracing::warn!(%node_id, error = %e, "desired_workload_approvals_withheld");
            None
        }
    }
}

/// The audit row's details: never the document, only what identifies it.
pub fn audit_details(node_id: &str, a: &Accepted) -> Value {
    json!({"node": node_id, "generation": a.generation, "entries": a.entries, "doc_sha256": a.doc_sha256, "doc": b64(&a.doc)})
}

fn plain(status: StatusCode, code: &str, detail: impl Into<String>) -> Response {
    (status, Json(json!({"error": code, "detail": detail.into()}))).into_response()
}

fn refused(r: &Refused) -> Response {
    plain(r.status, r.code, r.detail.clone())
}

fn answer(node_id: &str, a: &Accepted, changed: bool) -> Response {
    (
        StatusCode::OK,
        Json(json!({"node": node_id, "generation": a.generation, "entries": a.entries, "doc_sha256": a.doc_sha256, "changed": changed})),
    )
        .into_response()
}

/// The 200 for a set that was stored (and audited).
fn written(node_id: &str, a: &Accepted) -> Response {
    answer(node_id, a, true)
}

/// The 200 for a PUT of exactly the stored set: nothing was written.
fn unchanged(node_id: &str, a: &Accepted) -> Response {
    answer(node_id, a, false)
}

/// PUT /api/cluster/nodes/{node_id}/workload-approvals — store the
/// operator's signed set for an enrolled node, if it is newer. Operator only;
/// audited (`node_workload_approvals_set`).
pub async fn put_workload_approvals(
    State(state): State<Arc<AppState>>,
    operator: crate::authz::Operator,
    Path(node_id): Path<String>,
    body: Bytes,
) -> Response {
    match repo::node_enrolled(&state.db, &node_id).await {
        Ok(true) => {}
        Ok(false) => return plain(StatusCode::NOT_FOUND, code::UNKNOWN_NODE, format!("{node_id:?} is not a node this controller enrolled")),
        Err(e) => return plain(StatusCode::SERVICE_UNAVAILABLE, "unavailable", format!("reading the enrolled nodes: {e}")),
    }
    let stored = match repo::get(&state.db, &node_id).await {
        Ok(s) => s,
        Err(e) => return plain(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("reading {node_id}'s approval set: {e}")),
    };
    let verdict = match validate_put(&node_id, stored.as_ref().map(|s| (s.generation, s.doc.as_slice())), &body) {
        Ok(v) => v,
        Err(r) => return refused(&r),
    };
    let a = match verdict {
        Verdict::Unchanged(a) => return unchanged(&node_id, &a),
        Verdict::Store(a) => a,
    };
    let actor = operator.sub().to_string();
    match repo::store(&state.db, &node_id, a.generation, &a.doc, &a.sig, &actor).await {
        Ok(true) => {}
        Ok(false) => {
            return plain(StatusCode::CONFLICT, code::RACED, format!("another set for {node_id} at generation {} or above was stored meanwhile: read it and sign above it", a.generation))
        }
        Err(e) => return plain(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("storing {node_id}'s approval set: {e}")),
    }
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::NodeWorkloadApprovalsSet, &actor, &format!("node:{node_id}")).details(audit_details(&node_id, &a)),
    )
    .await;
    tracing::info!(node = %node_id, generation = a.generation, entries = a.entries, "node_workload_approvals_stored");
    super::cluster::nudge_reconcile(state.clone(), node_id.clone());
    written(&node_id, &a)
}

/// GET /api/cluster/nodes/{node_id}/workload-approvals — the stored set:
/// `{node, generation, doc, sig, stored_at, stored_by}` (doc and sig base64),
/// or 404. Operator only.
pub async fn get_workload_approvals(State(state): State<Arc<AppState>>, _op: crate::authz::Operator, Path(node_id): Path<String>) -> Response {
    match repo::get(&state.db, &node_id).await {
        Ok(Some(s)) => (StatusCode::OK, Json(stored_json(&s))).into_response(),
        Ok(None) => plain(StatusCode::NOT_FOUND, "not_found", format!("no approval set is stored for {node_id:?}")),
        Err(e) => plain(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("reading {node_id}'s approval set: {e}")),
    }
}

fn stored_json(s: &StoredSet) -> Value {
    json!({
        "node": s.node_id,
        "generation": s.generation,
        "doc": b64(&s.doc),
        "sig": b64(&s.sig),
        "stored_at": s.stored_at.to_rfc3339(),
        "stored_by": s.stored_by,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "nodea";

    fn entry(addon: &str, hex_char: char) -> Value {
        json!({"addon": addon, "digest": format!("sha256:{}", hex_char.to_string().repeat(64))})
    }

    fn doc_with(f: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut d = json!({
            "kind": SET_KIND,
            "node": NODE,
            "generation": 2,
            "issued_at": "2026-11-09T10:00:00Z",
            "approvals": [entry("rhaddon", 'a'), entry("rhaddon", 'b')],
        });
        f(&mut d);
        serde_json::to_vec(&d).unwrap()
    }

    fn good_doc() -> Vec<u8> {
        doc_with(|_| {})
    }

    fn body_of(doc: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({"doc": b64(doc), "sig": b64(b"a-der-signature")})).unwrap()
    }

    fn code_of(r: Result<Verdict, Refused>) -> &'static str {
        match r {
            Ok(v) => panic!("expected a refusal, got {v:?}"),
            Err(r) => r.code,
        }
    }

    fn status_of(r: Result<Verdict, Refused>) -> StatusCode {
        r.expect_err("expected a refusal").status
    }

    /// The control: a well-formed set above the stored generation is stored,
    /// and what is stored is the exact bytes and their SHA-256.
    #[test]
    fn a_well_formed_newer_set_is_stored_as_exact_bytes() {
        let doc = good_doc();
        let v = validate_put(NODE, Some((1, b"older".as_slice())), &body_of(&doc)).expect("accepted");
        let Verdict::Store(a) = v else { panic!("a newer set is stored") };
        assert_eq!((a.generation, a.entries), (2, 2));
        assert_eq!(a.doc, doc, "the exact bytes, never re-serialized");
        assert_eq!(a.sig, b"a-der-signature");
        assert_eq!(a.doc_sha256, hex::encode(Sha256::digest(&doc)));
        assert!(matches!(validate_put(NODE, None, &body_of(&doc)), Ok(Verdict::Store(_))), "no stored set: stored");
        // An empty list is a set (a revoke of everything), not a refusal.
        let none = doc_with(|d| d["approvals"] = json!([]));
        assert!(matches!(validate_put(NODE, None, &body_of(&none)), Ok(Verdict::Store(_))));
    }

    #[test]
    fn a_body_over_the_bound_is_refused() {
        let big = " ".repeat(MAX_BODY_BYTES + 1).into_bytes();
        let r = validate_put(NODE, None, &big);
        assert_eq!(status_of(r.clone()), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(code_of(r), code::TOO_LARGE);
    }

    #[test]
    fn a_document_over_the_bound_is_refused() {
        let pad = "x".repeat(MAX_DOC_BYTES);
        let doc = doc_with(|d| d["issued_at"] = json!(pad));
        assert!(body_of(&doc).len() <= MAX_BODY_BYTES, "the body bound is not what refuses it");
        assert_eq!(code_of(validate_put(NODE, None, &body_of(&doc))), code::TOO_LARGE);
    }

    #[test]
    fn a_signature_over_the_bound_is_refused() {
        let body = serde_json::to_vec(&json!({"doc": b64(&good_doc()), "sig": b64(&[7u8; MAX_SIG_BYTES + 1])})).unwrap();
        assert_eq!(code_of(validate_put(NODE, None, &body)), code::TOO_LARGE);
    }

    #[test]
    fn a_body_with_an_unknown_field_is_refused() {
        let body = serde_json::to_vec(&json!({"doc": b64(&good_doc()), "sig": b64(b"s"), "key": "fleet-signing"})).unwrap();
        assert_eq!(code_of(validate_put(NODE, None, &body)), code::BAD_BODY);
    }

    #[test]
    fn a_body_with_data_after_it_is_refused() {
        let mut body = body_of(&good_doc());
        body.extend_from_slice(b" []");
        assert_eq!(code_of(validate_put(NODE, None, &body)), code::BAD_BODY);
    }

    #[test]
    fn a_doc_that_is_not_base64_is_refused() {
        let body = serde_json::to_vec(&json!({"doc": "not base64!", "sig": b64(b"s")})).unwrap();
        assert_eq!(code_of(validate_put(NODE, None, &body)), code::BAD_BASE64);
    }

    #[test]
    fn a_sig_that_is_not_base64_is_refused() {
        let body = serde_json::to_vec(&json!({"doc": b64(&good_doc()), "sig": "not base64!"})).unwrap();
        assert_eq!(code_of(validate_put(NODE, None, &body)), code::BAD_BASE64);
    }

    #[test]
    fn a_doc_with_an_unknown_field_is_refused() {
        let doc = doc_with(|d| d["note"] = json!("extra"));
        assert_eq!(code_of(validate_put(NODE, None, &body_of(&doc))), code::DOC_INVALID);
    }

    #[test]
    fn an_entry_with_an_unknown_field_is_refused() {
        let doc = doc_with(|d| d["approvals"][0]["pattern"] = json!(true));
        assert_eq!(code_of(validate_put(NODE, None, &body_of(&doc))), code::DOC_INVALID);
    }

    #[test]
    fn a_doc_with_data_after_it_is_refused() {
        let mut doc = good_doc();
        doc.extend_from_slice(b" []");
        assert_eq!(code_of(validate_put(NODE, None, &body_of(&doc))), code::DOC_INVALID);
    }

    #[test]
    fn a_doc_of_another_kind_is_refused() {
        let doc = doc_with(|d| d["kind"] = json!("noo-model-set/1"));
        assert_eq!(code_of(validate_put(NODE, None, &body_of(&doc))), code::WRONG_KIND);
    }

    #[test]
    fn a_set_bound_to_another_node_than_the_path_is_refused() {
        let doc = doc_with(|d| d["node"] = json!("nodeb"));
        assert_eq!(code_of(validate_put(NODE, None, &body_of(&doc))), code::NODE_MISMATCH);
    }

    #[test]
    fn generation_zero_is_refused() {
        let doc = doc_with(|d| d["generation"] = json!(0));
        assert_eq!(code_of(validate_put(NODE, None, &body_of(&doc))), code::BAD_GENERATION);
    }

    #[test]
    fn an_issued_at_that_is_not_rfc3339_is_refused() {
        let doc = doc_with(|d| d["issued_at"] = json!("yesterday"));
        assert_eq!(code_of(validate_put(NODE, None, &body_of(&doc))), code::BAD_ISSUED_AT);
    }

    #[test]
    fn a_generation_below_the_stored_one_is_refused() {
        let r = validate_put(NODE, Some((3, b"held".as_slice())), &body_of(&good_doc()));
        assert_eq!(status_of(r.clone()), StatusCode::CONFLICT);
        assert_eq!(code_of(r), code::GENERATION_ROLLBACK);
    }

    #[test]
    fn the_stored_generation_with_other_bytes_is_a_409() {
        let r = validate_put(NODE, Some((2, b"other bytes".as_slice())), &body_of(&good_doc()));
        assert_eq!(status_of(r.clone()), StatusCode::CONFLICT);
        assert_eq!(code_of(r), code::GENERATION_CONFLICT);
    }

    #[test]
    fn the_stored_generation_with_the_stored_bytes_is_idempotent() {
        let doc = good_doc();
        let v = validate_put(NODE, Some((2, doc.as_slice())), &body_of(&doc)).expect("idempotent");
        assert!(matches!(v, Verdict::Unchanged(_)), "nothing to write: {v:?}");
    }

    #[test]
    fn a_digest_that_is_not_one_exact_sha256_is_refused() {
        for bad in [format!("sha256:{}", "A".repeat(64)), format!("sha256:{}", "a".repeat(63)), "sha256:*".to_string(), "a".repeat(64)] {
            let doc = doc_with(|d| d["approvals"][0]["digest"] = json!(bad));
            assert_eq!(code_of(validate_put(NODE, None, &body_of(&doc))), code::BAD_DIGEST, "{bad}");
        }
    }

    /// The gateway's add-on name rule: a name the agent's pattern alone
    /// would take (a leading digit, a reserved core name).
    #[test]
    fn an_addon_outside_the_gateways_name_rule_is_refused() {
        for bad in ["9rhaddon", "worker"] {
            let doc = doc_with(|d| d["approvals"][0]["addon"] = json!(bad));
            assert_eq!(code_of(validate_put(NODE, None, &body_of(&doc))), code::BAD_ADDON, "{bad}");
        }
    }

    /// The agent's pattern: a name the gateway's rule alone would take (an
    /// underscore, a trailing dash), which every node would refuse whole.
    #[test]
    fn an_addon_outside_the_agents_pattern_is_refused() {
        for bad in ["rh_addon", "rhaddon-"] {
            assert!(crate::addon_registry::name_ok(bad), "{bad}: the gateway's own rule takes it");
            let doc = doc_with(|d| d["approvals"][0]["addon"] = json!(bad));
            assert_eq!(code_of(validate_put(NODE, None, &body_of(&doc))), code::BAD_ADDON, "{bad}");
        }
    }

    #[test]
    fn a_duplicate_entry_is_refused() {
        let doc = doc_with(|d| d["approvals"] = json!([entry("rhaddon", 'a'), entry("rhaddon", 'a')]));
        assert_eq!(code_of(validate_put(NODE, None, &body_of(&doc))), code::DUPLICATE_ENTRY);
    }

    /// The audit row names the node, generation, entry count and the
    /// document's SHA-256, and never carries the document or the signature.
    #[test]
    fn the_audit_details_identify_the_set_without_carrying_it() {
        let doc = good_doc();
        let Ok(Verdict::Store(a)) = validate_put(NODE, None, &body_of(&doc)) else { panic!("accepted") };
        let d = audit_details(NODE, &a);
        let keys: Vec<&str> = d.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys.len(), 4, "{d}");
        assert_eq!((d["node"].as_str(), d["generation"].as_i64(), d["entries"].as_u64()), (Some(NODE), Some(2), Some(2)));
        assert_eq!(d["doc_sha256"].as_str(), Some(hex::encode(Sha256::digest(&doc)).as_str()));
        assert!(!d.to_string().contains(&b64(&doc)));
    }

    fn stored(doc: &[u8], sig: &[u8]) -> StoredSet {
        StoredSet { node_id: NODE.into(), generation: 4, doc: doc.to_vec(), sig: sig.to_vec(), stored_at: chrono::Utc::now(), stored_by: "alice".into() }
    }

    /// desired-config: nothing stored is NO key (never null); a stored set is
    /// `{doc, sig}`, its exact bytes as base64, and nothing else.
    #[test]
    fn the_desired_field_is_absent_without_a_set_and_the_exact_pair_with_one() {
        assert_eq!(desired_field(None), None);
        let v = desired_field(Some(&stored(b"doc-bytes", b"sig-bytes"))).expect("a stored set is carried");
        assert_eq!(v, json!({"doc": b64(b"doc-bytes"), "sig": b64(b"sig-bytes")}));
        assert!(!v.is_null());
    }

    /// GET returns the stored set as the slice 3 CLI reads it.
    #[test]
    fn the_get_body_is_the_stored_set() {
        let v = stored_json(&stored(b"d", b"s"));
        assert_eq!((v["node"].as_str(), v["generation"].as_i64(), v["stored_by"].as_str()), (Some(NODE), Some(4), Some("alice")));
        assert_eq!((v["doc"].as_str(), v["sig"].as_str()), (Some(b64(b"d").as_str()), Some(b64(b"s").as_str())));
        assert!(v["stored_at"].as_str().is_some_and(|t| chrono::DateTime::parse_from_rfc3339(t).is_ok()));
    }

    /// Both routes take the operator extractor: it runs before the body, and
    /// it refuses a call that names no person (no cluster HMAC, no node).
    #[test]
    fn both_routes_are_operator_only() {
        let own = crate::test_src::own_code(include_str!("node_workload_approvals.rs"));
        for f in ["async fn put_workload_approvals(", "async fn get_workload_approvals("] {
            let h = crate::test_src::fn_body(&own, f);
            assert!(h.contains(": crate::authz::Operator,"), "{f} is operator-gated");
            assert!(!h.contains("OperatorOrInternal"), "{f}: not the internal-callers policy");
        }
    }

    /// The PUT's order: the node is enrolled before anything is judged; the
    /// set is judged, then stored, then audited, then the node nudged, and
    /// only then the 200. One store, one audit.
    #[test]
    fn the_put_checks_then_stores_then_audits_then_answers() {
        let own = crate::test_src::own_code(include_str!("node_workload_approvals.rs"));
        let put = crate::test_src::fn_body(&own, "async fn put_workload_approvals(");
        let at = |s: &str| put.find(s).unwrap_or_else(|| panic!("{s} is gone"));
        let order = [
            at("repo::node_enrolled("),
            at("validate_put("),
            at("repo::store("),
            at("AuditKind::NodeWorkloadApprovalsSet"),
            at("super::cluster::nudge_reconcile(state.clone(), node_id.clone());"),
            at("written(&node_id, &a)"),
        ];
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}");
        assert_eq!(put.matches("repo::store(").count(), 1);
        assert_eq!(put.matches("crate::audit::record(").count(), 1);
        assert!(at("Ok(false) => return plain(StatusCode::NOT_FOUND, code::UNKNOWN_NODE") < at("validate_put("), "an unknown node is a 404");
    }
}
