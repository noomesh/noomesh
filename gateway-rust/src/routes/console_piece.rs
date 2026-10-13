// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Console pieces: an add-on serves its own part of the console diagrams.
//!
//! The console's diagrams ship with empty slots for add-on lanes; an installed
//! add-on fills them. `GET /api/addons/{addon_id}/console-piece` fetches that
//! add-on's piece and hands the console a validated copy.
//!
//! Slot ids are `<addon>:<name>`. A piece is
//! `{"version": 1, "addon": "<id>", "slots": {"<slotId>": {"title", "description", "steps"}}}`.
//!
//! Two transports, because the two add-ons speak different ones:
//!
//! - `evolve` is HTTP: the manifest's internal `console_piece` route, reached
//!   through [`crate::addon_proxy::call`].
//! - `trellion_intel` is NATS: request `worker.graph.console_piece`.
//!
//! Status codes: unknown id 404 `{"error":"unknown_addon"}`; add-on disabled or
//! unlicensed 503 with [`crate::addons::refusal_msg`]; enabled but no answer,
//! a timeout, a non-200 upstream or a piece that fails validation 502. Never 500.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde_json::{json, Map, Value};

use crate::state::AppState;

/// The only subject this route publishes. Inside the intel `worker.graph.*`
/// family, so `addons::is_trellion_intel_subject` already gates it.
pub(crate) const SUBJECT_INTEL_CONSOLE_PIECE: &str = "worker.graph.console_piece";
const INTEL_TIMEOUT: Duration = Duration::from_secs(5);
/// A piece is a few paragraphs of text. Anything near this is a bug upstream.
const MAX_PIECE_BYTES: usize = 64 * 1024;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/addons/{addon_id}/console-piece", get(console_piece))
}

/// GET /api/addons/{addon_id}/console-piece — the add-on's piece of the
/// console diagrams (slots `<addon_id>:*`). 404 unknown add-on, 503 disabled
/// or unlicensed, 502 when the add-on does not answer with a valid piece.
async fn console_piece(
    State(state): State<Arc<AppState>>,
    Path(addon_id): Path<String>,
) -> (StatusCode, Json<Value>) {
    let (status, body) = respond(&addon_id, Some(&state.nats)).await;
    (status, Json(body))
}

fn bad_gateway(addon: &str, why: impl std::fmt::Display) -> (StatusCode, Value) {
    tracing::warn!(addon, "console piece unavailable: {why}");
    (
        StatusCode::BAD_GATEWAY,
        json!({ "error": "console_piece_unavailable", "addon": addon, "detail": why.to_string() }),
    )
}

async fn respond(addon_id: &str, nats: Option<&async_nats::Client>) -> (StatusCode, Value) {
    let addon = match addon_id {
        "evolve" => "evolve",
        "trellion_intel" => "trellion_intel",
        _ => return (StatusCode::NOT_FOUND, json!({ "error": "unknown_addon" })),
    };
    if !crate::addons::enabled(addon) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": crate::addons::refusal_msg(addon),
                "addon": addon,
                "state": crate::addons::health_word(addon),
            }),
        );
    }
    let raw = match addon {
        "evolve" => match crate::addon_proxy::call("evolve", "console_piece", None).await {
            crate::addon_proxy::CallOutcome::Ok(v) => v,
            crate::addon_proxy::CallOutcome::Unavailable(why) => return bad_gateway(addon, why),
        },
        _ => {
            let Some(nats) = nats else {
                return bad_gateway(addon, "no bus connection");
            };
            match crate::worker_client::request_with_timeout(
                nats,
                SUBJECT_INTEL_CONSOLE_PIECE,
                &json!({}),
                INTEL_TIMEOUT,
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return bad_gateway(addon, e),
            }
        }
    };
    match validate_piece(addon, &raw) {
        Ok(piece) => (StatusCode::OK, piece),
        Err(why) => bad_gateway(addon, format!("invalid piece: {why}")),
    }
}

/// Check a piece against the contract and return a normalized copy (only the
/// known fields per slot survive). `Err` names the first violation.
pub(crate) fn validate_piece(addon: &str, raw: &Value) -> Result<Value, String> {
    // A NATS worker may wrap its reply in a `data` envelope; accept either.
    let piece = match (raw.get("version"), raw.get("data")) {
        (None, Some(d)) if d.is_object() => d,
        _ => raw,
    };
    let obj = piece.as_object().ok_or("not a JSON object")?;
    if obj.get("version") != Some(&json!(1)) {
        return Err("version must be 1".into());
    }
    match obj.get("addon").and_then(Value::as_str) {
        Some(a) if a == addon => {}
        other => return Err(format!("addon is {other:?}, expected {addon:?}")),
    }
    let slots = obj
        .get("slots")
        .and_then(Value::as_object)
        .ok_or("slots must be an object")?;
    let prefix = format!("{addon}:");
    let mut out = Map::new();
    for (key, slot) in slots {
        if !key.starts_with(&prefix) || key.len() == prefix.len() {
            return Err(format!("slot key {key:?} must start with {prefix:?}"));
        }
        let s = slot
            .as_object()
            .ok_or_else(|| format!("slot {key:?} is not an object"))?;
        let text = |f: &str| -> Result<&str, String> {
            s.get(f)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("slot {key:?}: {f} must be a string"))
        };
        let mut entry = json!({ "title": text("title")?, "description": text("description")? });
        // `steps` is optional; when present it is an array of strings.
        if let Some(steps) = s.get("steps") {
            let steps = steps
                .as_array()
                .ok_or_else(|| format!("slot {key:?}: steps must be an array of strings"))?
                .iter()
                .map(|v| {
                    v.as_str()
                        .ok_or_else(|| format!("slot {key:?}: steps must be an array of strings"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            entry["steps"] = json!(steps);
        }
        out.insert(key.clone(), entry);
    }
    let piece = json!({ "version": 1, "addon": addon, "slots": out });
    let size = serde_json::to_vec(&piece).map(|b| b.len()).unwrap_or(usize::MAX);
    if size >= MAX_PIECE_BYTES {
        return Err(format!("piece is {size} bytes; the limit is under {MAX_PIECE_BYTES}"));
    }
    Ok(piece)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good(addon: &str) -> Value {
        json!({
            "version": 1, "addon": addon,
            "slots": { format!("{addon}:x"): { "title": "T", "description": "D", "steps": ["a", "b"] } }
        })
    }

    #[test]
    fn a_good_piece_passes_and_is_normalized() {
        let mut p = good("evolve");
        p["slots"]["evolve:x"]["extra"] = json!("dropped");
        let out = validate_piece("evolve", &p).expect("valid");
        assert_eq!(out["slots"]["evolve:x"]["steps"], json!(["a", "b"]));
        assert!(out["slots"]["evolve:x"].get("extra").is_none());
        assert!(validate_piece("trellion_intel", &good("trellion_intel")).is_ok());
    }

    #[test]
    fn empty_steps_absent_steps_and_empty_slots_are_fine() {
        let mut p = good("evolve");
        p["slots"]["evolve:x"]["steps"] = json!([]);
        assert!(validate_piece("evolve", &p).is_ok());
        p["slots"]["evolve:x"].as_object_mut().unwrap().remove("steps");
        let out = validate_piece("evolve", &p).expect("absent steps is valid");
        assert!(out["slots"]["evolve:x"].get("steps").is_none());
        assert!(validate_piece("evolve", &json!({"version":1,"addon":"evolve","slots":{}})).is_ok());
    }

    #[test]
    fn a_nats_data_envelope_is_unwrapped() {
        let wrapped = json!({ "success": true, "data": good("trellion_intel") });
        assert!(validate_piece("trellion_intel", &wrapped).is_ok());
        // An envelope with no piece inside is not a piece.
        assert!(validate_piece("trellion_intel", &json!({ "success": true })).is_err());
        assert!(validate_piece("trellion_intel", &json!({ "success": true, "data": null })).is_err());
        // The envelope's inner piece is validated like any other.
        let mut inner = good("trellion_intel");
        inner["version"] = json!(2);
        assert!(validate_piece("trellion_intel", &json!({ "success": true, "data": inner })).is_err());
    }

    #[test]
    fn wrong_version_is_refused() {
        for v in [json!(2), json!("1"), json!(null)] {
            let mut p = good("evolve");
            p["version"] = v;
            assert!(validate_piece("evolve", &p).is_err());
        }
        let mut p = good("evolve");
        p.as_object_mut().unwrap().remove("version");
        assert!(validate_piece("evolve", &p).is_err());
    }

    #[test]
    fn an_addon_mismatch_is_refused() {
        assert!(validate_piece("evolve", &good("trellion_intel")).is_err());
        // The slot keys are right for the add-on asked about; only the
        // declared `addon` field lies. That alone must be refused.
        let mut p = good("evolve");
        p["addon"] = json!("trellion_intel");
        assert!(validate_piece("evolve", &p).is_err());
        let mut p = good("evolve");
        p.as_object_mut().unwrap().remove("addon");
        assert!(validate_piece("evolve", &p).is_err());
    }

    #[test]
    fn a_slot_key_outside_the_addons_prefix_is_refused() {
        for key in ["trellion_intel:temporal", "evolve", "evolve:", "other"] {
            let mut p = good("evolve");
            p["slots"] = json!({ key: { "title": "T", "description": "D", "steps": [] } });
            assert!(validate_piece("evolve", &p).is_err(), "{key}");
        }
    }

    #[test]
    fn non_string_values_are_refused() {
        for (field, bad) in [
            ("title", json!(1)),
            ("description", json!(null)),
            ("steps", json!("a")),
            ("steps", json!(null)),
            ("steps", json!(["a", 2])),
        ] {
            let mut p = good("evolve");
            p["slots"]["evolve:x"][field] = bad;
            assert!(validate_piece("evolve", &p).is_err(), "{field}");
        }
        let mut p = good("evolve");
        p["slots"]["evolve:x"] = json!("flat string");
        assert!(validate_piece("evolve", &p).is_err());
        assert!(validate_piece("evolve", &json!([1])).is_err());
    }

    #[test]
    fn an_oversize_piece_is_refused() {
        let mut p = good("evolve");
        p["slots"]["evolve:x"]["description"] = json!("x".repeat(MAX_PIECE_BYTES));
        assert!(validate_piece("evolve", &p).is_err());
    }

    #[tokio::test]
    async fn an_unknown_addon_is_404() {
        let (status, body) = respond("nope", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, json!({ "error": "unknown_addon" }));
        // trellion (the open pack) owns no slots, so it is unknown here too.
        assert_eq!(respond("trellion", None).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_disabled_addon_is_503_with_the_refusal_text() {
        // Both add-ons are opt-in and the test env sets neither flag.
        for id in ["evolve", "trellion_intel"] {
            let (status, body) = respond(id, None).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{id}");
            assert_eq!(body["error"], json!(crate::addons::refusal_msg(id)), "{id}");
        }
    }

    #[test]
    fn the_subject_is_inside_the_intel_family() {
        assert!(crate::addons::is_trellion_intel_subject(SUBJECT_INTEL_CONSOLE_PIECE));
        assert!(!crate::addons::is_trellion_subject(SUBJECT_INTEL_CONSOLE_PIECE));
    }

    #[test]
    fn the_piece_route_must_be_internal_in_any_manifest() {
        // The gateway fetches and validates the piece; an add-on cannot
        // publish the route itself (addon_proxy::CALLED_BY_NAME).
        assert!(crate::addon_proxy::CALLED_BY_NAME.contains(&"console_piece"));
        let mut m = crate::addon_proxy::tests::sample();
        m.routes.iter_mut().find(|r| r.name == "console_piece").unwrap().internal = false;
        assert!(crate::addon_proxy::validate(&m, "evolve").unwrap_err().contains("internal"));
    }
}
