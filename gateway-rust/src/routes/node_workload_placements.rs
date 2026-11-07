// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Operator placement of an add-on node workload on ONE node (i300 H3b-2).
//!
//! ```text
//! PUT    /api/cluster/nodes/{node_id}/node-workloads/{addon}/{workload}
//!        {"profile": "int8", "sets": {"main": [{"id", "revision"}]},
//!         "env": {"RHADDON_SLOTS": "1"}, "on_controller": false}
//! DELETE /api/cluster/nodes/{node_id}/node-workloads/{addon}/{workload}
//! GET    /api/cluster/nodes/{node_id}/node-workloads
//! ```
//!
//! A PUT is accepted only when the entry the gateway would send the node
//! validates exactly as the agent will validate it, and the node passes
//! every hard filter. [`plan`] builds the desired-config entry
//! (`docs/reference/node-workloads.md`): the declaration verbatim, the image
//! from the rail ({name, digest, id, artifact} for the node's arch), the
//! sets, env and profile asked for, the door (leaf `svc-addon-<a>-<w>`,
//! admit exactly the node's agent), and state `provisioned`. It runs the
//! one desired validator and `check_profile` against the staged main set,
//! then derives what [`crate::workload_placement::check`] needs: GPU, the
//! profile's `min_compute`, the set's arch, and the bytes of every set.
//!
//! A refusal answers `{"error": <the agent's reason code>, "detail"}`: 400
//! for what the request got wrong (sets, profile, env), 404 for an unknown
//! add-on, workload or node, 409 for what the node or the controller cannot
//! do (the hard filters, a missing image or set, a placement on another node).
//! Nothing is written on a refusal.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::node_workload_sources::{self as sources, RailImage};
use crate::node_workloads::{check_profile, code, validate_desired_entry, Decl, ModelSet, Refusal, SetRef};
use crate::repo::node_workload_placements::{self as repo, Placed, Placement};
use crate::state::AppState;
use crate::workload_placement::{self as filters, Needs, SetNeed};

/// The PUT body.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutBody {
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub sets: BTreeMap<String, Vec<SetRef>>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// The operator opts in to the controller's own host (D4).
    #[serde(default)]
    pub on_controller: bool,
}

/// The desired-config entry for the placement, and what the hard filters need.
#[derive(Debug, Clone)]
pub struct Plan {
    pub entry: Value,
    pub needs: Needs,
    pub image: RailImage,
}

/// The rail and staged-set readers [`plan`] uses, so a test can stand in for
/// the controller's directories.
pub trait Sources {
    fn rail_image(&self, addon: &str, image: &str, arch: &str) -> Result<RailImage, Refusal>;
    fn staged_set(&self, id: &str, revision: &str) -> Result<(ModelSet, u64), Refusal>;
}

/// The controller's own directories.
pub struct ControllerSources {
    pub images: PathBuf,
    pub sets: PathBuf,
}

impl Sources for ControllerSources {
    fn rail_image(&self, addon: &str, image: &str, arch: &str) -> Result<RailImage, Refusal> {
        sources::rail_image(&self.images, addon, image, arch)
    }
    fn staged_set(&self, id: &str, revision: &str) -> Result<(ModelSet, u64), Refusal> {
        sources::staged_set(&self.sets, id, revision)
    }
}

/// The node's arch as its agent reports it (`runtime.GOARCH`).
fn node_arch(node: &Value) -> Option<&str> {
    node.pointer("/capabilities/arch").or_else(|| node.get("arch")).and_then(Value::as_str).filter(|a| !a.is_empty())
}

/// Build and validate the entry for `addon`'s workload `decl` (`decl_raw` the
/// same object as the file carries it) on `node_id`, and derive the filter
/// needs. The first refusal wins.
pub fn plan(addon: &str, decl: &Decl, decl_raw: &Value, node_id: &str, node: &Value, body: &PutBody, src: &dyn Sources) -> Result<Plan, Refusal> {
    let Some(arch) = node_arch(node) else {
        return Err(Refusal::new(code::ARCH_MISMATCH, "the node does not report its arch, so its image cannot be chosen"));
    };
    let image = src.rail_image(addon, &decl.image, arch)?;
    let entry = json!({
        "addon": addon,
        "name": decl.name,
        "decl": decl_raw,
        "image": {"name": image.image, "digest": image.digest, "id": image.id, "artifact": image.artifact},
        "sets": body.sets,
        "env": body.env,
        "profile": body.profile,
        "door": {"leaf": format!("svc-addon-{addon}-{}", decl.name), "admit": [node_id]},
        "start_secs": decl_raw.pointer("/health/start_secs").cloned().unwrap_or(Value::Null),
        "drain": decl_raw.get("drain").cloned().unwrap_or(Value::Null),
        "reservation": Value::Null,
        "state": "provisioned",
    });
    let e = validate_desired_entry(&entry, node_id)?;

    // Every set the slots name must be staged; the main slot's set judges
    // the profile and gives min_compute and arch.
    let mut set_needs = Vec::new();
    let mut main: Option<ModelSet> = None;
    let main_slot = decl.models.first().map(|s| s.slot.as_str());
    for (slot, refs) in &body.sets {
        for (i, r) in refs.iter().enumerate() {
            let (set, bytes) = src.staged_set(&r.id, &r.revision)?;
            if Some(slot.as_str()) == main_slot && i == 0 {
                main = Some(set);
            }
            set_needs.push(SetNeed { id: r.id.clone(), revision: r.revision.clone(), bytes });
        }
    }
    let mut min_compute = None;
    let mut set_arch = Vec::new();
    if let Some(m) = &main {
        // As the agent's gate: only a set that lists profiles judges one.
        if !m.needs.profiles.is_empty() {
            check_profile(&e, m)?;
        }
        if let Some(p) = body.profile.as_deref() {
            min_compute = m.needs.profiles.iter().find(|x| x.name == p).map(|x| x.min_compute.clone()).filter(|c| !c.is_empty());
        }
        set_arch = m.needs.arch.clone();
    }
    let needs = Needs {
        addon: addon.to_string(),
        digest: image.digest.clone(),
        gpu: u32::try_from(decl.accel.gpu.max(0)).unwrap_or(u32::MAX),
        min_compute,
        arch: set_arch,
        sets: set_needs,
        on_controller: body.on_controller,
    };
    Ok(Plan { entry, needs, image })
}

/// The HTTP status for a refusal code: the request's fault, or the node's.
pub fn refusal_status(c: &str) -> StatusCode {
    match c {
        code::SET_MISSING | code::SET_SLOT_INVALID | code::PROFILE_INVALID | code::ENV_OUT_OF_BOUNDS | code::DESIRED_INVALID => {
            StatusCode::BAD_REQUEST
        }
        _ => StatusCode::CONFLICT,
    }
}

fn refused(r: &Refusal) -> Response {
    (refusal_status(r.code), Json(json!({"error": r.code, "detail": r.to_string()}))).into_response()
}

fn plain(status: StatusCode, code: &str, detail: impl Into<String>) -> Response {
    (status, Json(json!({"error": code, "detail": detail.into()}))).into_response()
}

async fn node_record(state: &AppState, node_id: &str) -> Result<Option<Value>, String> {
    let kv = state.js.get_key_value("mesh_nodes").await.map_err(|e| format!("mesh_nodes: {e}"))?;
    let entry = kv.get(node_id).await.map_err(|e| format!("mesh_nodes {node_id}: {e}"))?;
    Ok(entry.and_then(|b| serde_json::from_slice::<Value>(&b).ok()))
}

fn names_ok(addon: &str, workload: &str) -> bool {
    crate::addon_registry::name_ok(addon) && crate::addon_workloads::workload_name_ok(workload)
}

/// PUT /api/cluster/nodes/{node_id}/node-workloads/{addon}/{workload}
pub async fn put_placement(
    State(state): State<Arc<AppState>>,
    Path((node_id, addon, workload)): Path<(String, String, String)>,
    Json(body): Json<PutBody>,
) -> Response {
    if !names_ok(&addon, &workload) {
        return plain(StatusCode::BAD_REQUEST, "bad_request", "add-on and workload must be valid names");
    }
    let decls = match sources::declared(&addon) {
        Ok(Some(d)) => d,
        Ok(None) => return plain(StatusCode::NOT_FOUND, "not_found", format!("{addon} is not a registered add-on with node workloads")),
        Err(r) => return refused(&r),
    };
    let Some(decl) = decls.workloads.iter().find(|w| w.name == workload) else {
        return plain(StatusCode::NOT_FOUND, "not_found", format!("{addon} declares no node workload {workload:?}"));
    };
    let Some(raw) = sources::raw_workload(std::path::Path::new(crate::addon_decls::WORKLOADS_DIR), &addon, &workload) else {
        return plain(StatusCode::CONFLICT, code::DECL_INVALID, format!("{addon}'s node-workloads.json could not be read again"));
    };
    let node = match node_record(&state, &node_id).await {
        Ok(Some(n)) => n,
        Ok(None) => return plain(StatusCode::NOT_FOUND, "not_found", format!("no node {node_id:?} reports to this controller")),
        Err(e) => return plain(StatusCode::SERVICE_UNAVAILABLE, "unavailable", e),
    };
    let src = ControllerSources { images: crate::routes::artifacts::image_dir(), sets: crate::routes::artifacts::gguf_dir().join("sets") };
    let p = match plan(&addon, decl, &raw, &node_id, &node, &body, &src) {
        Ok(p) => p,
        Err(r) => return refused(&r),
    };
    if let Err(r) = filters::check(&node, &p.needs) {
        return (refusal_status(r.code), Json(json!({"error": r.code, "detail": r.detail}))).into_response();
    }
    let row = Placement {
        addon: addon.clone(),
        workload: workload.clone(),
        node_id: node_id.clone(),
        profile: body.profile.clone(),
        sets: json!(body.sets),
        env: json!(body.env),
        on_controller: body.on_controller,
        desired_state: "provisioned".into(),
        reservation: None,
    };
    match repo::place(&state.db, &row).await {
        Ok(Placed::Written) => {
            tracing::info!(%node_id, %addon, %workload, image = %p.image.artifact, "node_workload_placed");
            (StatusCode::OK, Json(json!({"node_id": node_id, "addon": addon, "workload": workload, "state": "provisioned", "image": p.entry["image"]})))
                .into_response()
        }
        Ok(Placed::OnOtherNode(other)) => plain(
            StatusCode::CONFLICT,
            "placed_elsewhere",
            format!("{addon}/{workload} is placed on {other}: remove it there first"),
        ),
        Ok(Placed::Raced) => plain(StatusCode::CONFLICT, "raced", "the placement changed while this one was written: try again"),
        Err(e) => plain(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("placing {addon}/{workload}: {e}")),
    }
}

/// DELETE /api/cluster/nodes/{node_id}/node-workloads/{addon}/{workload}
pub async fn delete_placement(State(state): State<Arc<AppState>>, Path((node_id, addon, workload)): Path<(String, String, String)>) -> Response {
    if !names_ok(&addon, &workload) {
        return plain(StatusCode::BAD_REQUEST, "bad_request", "add-on and workload must be valid names");
    }
    match repo::remove(&state.db, &node_id, &addon, &workload).await {
        Ok(true) => (StatusCode::OK, Json(json!({"node_id": node_id, "addon": addon, "workload": workload, "removed": true}))).into_response(),
        Ok(false) => plain(StatusCode::NOT_FOUND, "not_found", format!("{addon}/{workload} is not placed on {node_id}")),
        Err(e) => plain(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("removing {addon}/{workload}: {e}")),
    }
}

/// GET /api/cluster/nodes/{node_id}/node-workloads
pub async fn list_placements(State(state): State<Arc<AppState>>, Path(node_id): Path<String>) -> Response {
    match repo::for_node(&state.db, &node_id).await {
        Ok(rows) => {
            let v: Vec<Value> = rows
                .into_iter()
                .map(|r| {
                    json!({"addon": r.addon, "workload": r.workload, "profile": r.profile, "sets": r.sets, "env": r.env,
                           "on_controller": r.on_controller, "state": r.desired_state, "reservation": r.reservation})
                })
                .collect();
            (StatusCode::OK, Json(json!({"node_id": node_id, "node_workloads": v}))).into_response()
        }
        Err(e) => plain(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("listing {node_id}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const DIGEST_HEX: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ID: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn fixture(rel: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/testdata/i300").join(rel)).unwrap()
    }

    /// The desired fixture's first entry: the decl, sets, env and profile a
    /// valid placement asks for.
    fn fixture_entry() -> Value {
        let v: Value = serde_json::from_slice(&fixture("desired-node-workloads.json")).unwrap();
        v["node_workloads"][0].clone()
    }

    fn decl() -> (Decl, Value) {
        let raw = fixture_entry()["decl"].clone();
        let lock: BTreeSet<String> = [raw["image"].as_str().unwrap().to_string()].into();
        let file = json!({"format": "noo-addon-node-workloads/1", "workloads": [raw.clone()]});
        let parsed = crate::node_workloads::validate_decl(file.to_string().as_bytes(), "rhaddon", &lock, None).expect("fixture decl");
        (parsed.workloads[0].clone(), raw)
    }

    fn body() -> PutBody {
        let e = fixture_entry();
        PutBody {
            profile: e["profile"].as_str().map(str::to_string),
            sets: serde_json::from_value(e["sets"].clone()).unwrap(),
            env: serde_json::from_value(e["env"].clone()).unwrap(),
            on_controller: false,
        }
    }

    fn node() -> Value {
        json!({"id": "node-a", "capabilities": {"arch": "amd64"}})
    }

    /// The fixture's main set (it names the fixture entry's id, revision and
    /// profile) and a voice pack, standing in for the controller's store.
    struct Fake {
        main: Option<ModelSet>,
        missing_set: Option<String>,
    }

    fn main_set() -> ModelSet {
        let e = fixture_entry();
        let main = &e["sets"]["main"][0];
        let profile = e["profile"].as_str().unwrap();
        ModelSet {
            id: main["id"].as_str().unwrap().into(),
            revision: main["revision"].as_str().unwrap().into(),
            needs: crate::node_workloads::Needs {
                profiles: vec![crate::node_workloads::SetProfile { name: profile.into(), min_compute: "8.0".into(), realtime: Some(true), ..Default::default() }],
                arch: vec!["amd64".into()],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    impl Sources for Fake {
        fn rail_image(&self, addon: &str, image: &str, arch: &str) -> Result<RailImage, Refusal> {
            Ok(RailImage {
                image: image.into(),
                digest: format!("sha256:{DIGEST_HEX}"),
                id: ID.into(),
                artifact: format!("noo-addon-wl_{addon}_{image}_{DIGEST_HEX}_{arch}.tar"),
                arch: arch.into(),
            })
        }
        fn staged_set(&self, id: &str, revision: &str) -> Result<(ModelSet, u64), Refusal> {
            if self.missing_set.as_deref() == Some(id) {
                return Err(Refusal::new(code::SET_UNVERIFIED, "not staged"));
            }
            let m = self.main.clone().unwrap_or_default();
            if id == m.id {
                return Ok((m, 15 << 30));
            }
            Ok((ModelSet { id: id.into(), revision: revision.into(), ..Default::default() }, 1 << 20))
        }
    }

    fn fake() -> Fake {
        Fake { main: Some(main_set()), missing_set: None }
    }

    #[test]
    fn a_valid_placement_builds_the_entry_the_agent_accepts_and_its_needs() {
        let (d, raw) = decl();
        let p = plan("rhaddon", &d, &raw, "node-a", &node(), &body(), &fake()).expect("plan");
        // Exactly the fixture's entry, but for the image (from the rail).
        let mut want = fixture_entry();
        want["image"] = p.entry["image"].clone();
        assert_eq!(p.entry, want);
        assert_eq!(p.entry["door"], json!({"leaf": "svc-addon-rhaddon-worker", "admit": ["node-a"]}));
        crate::node_workloads::validate_desired_entry(&p.entry, "node-a").expect("the agent's validator accepts it");
        assert_eq!(p.needs.gpu, 1);
        assert_eq!(p.needs.min_compute.as_deref(), Some("8.0"));
        assert_eq!(p.needs.arch, vec!["amd64".to_string()]);
        assert_eq!(p.needs.digest, format!("sha256:{DIGEST_HEX}"));
        assert_eq!(p.needs.sets.len(), 2, "every set the slots name is sized");
        assert_eq!(p.needs.sets.iter().map(|s| s.bytes).sum::<u64>(), (15 << 30) + (1 << 20));
    }

    #[test]
    fn an_env_value_outside_its_bound_is_refused_before_any_filter() {
        let (d, raw) = decl();
        let mut b = body();
        b.env.insert("RHADDON_SLOTS".into(), "99".into());
        let r = plan("rhaddon", &d, &raw, "node-a", &node(), &b, &fake()).unwrap_err();
        assert_eq!(r.code, code::ENV_OUT_OF_BOUNDS);
        assert_eq!(refusal_status(r.code), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_missing_required_slot_and_an_undeclared_slot_are_refused() {
        let (d, raw) = decl();
        let mut b = body();
        b.sets.remove("main");
        assert_eq!(plan("rhaddon", &d, &raw, "node-a", &node(), &b, &fake()).unwrap_err().code, code::SET_MISSING);
        let mut b = body();
        b.sets.insert("extra".into(), vec![SetRef { id: "x".into(), revision: "r1".into() }]);
        assert_eq!(plan("rhaddon", &d, &raw, "node-a", &node(), &b, &fake()).unwrap_err().code, code::SET_SLOT_INVALID);
    }

    #[test]
    fn a_profile_the_main_set_does_not_have_is_refused() {
        let (d, raw) = decl();
        let mut b = body();
        b.profile = Some("fp64".into());
        assert_eq!(plan("rhaddon", &d, &raw, "node-a", &node(), &b, &fake()).unwrap_err().code, code::PROFILE_INVALID);
    }

    #[test]
    fn a_set_not_staged_on_the_controller_is_refused() {
        let (d, raw) = decl();
        let f = Fake { main: Some(main_set()), missing_set: Some(main_set().id) };
        let r = plan("rhaddon", &d, &raw, "node-a", &node(), &body(), &f).unwrap_err();
        assert_eq!(r.code, code::SET_UNVERIFIED);
        assert_eq!(refusal_status(r.code), StatusCode::CONFLICT);
    }

    #[test]
    fn a_node_without_an_arch_cannot_have_its_image_chosen() {
        let (d, raw) = decl();
        assert_eq!(plan("rhaddon", &d, &raw, "node-a", &json!({"id": "node-a"}), &body(), &fake()).unwrap_err().code, code::ARCH_MISMATCH);
    }

    #[test]
    fn the_door_admits_exactly_the_placed_nodes_agent() {
        let (d, raw) = decl();
        let p = plan("rhaddon", &d, &raw, "node-b", &json!({"id": "node-b", "capabilities": {"arch": "amd64"}}), &body(), &fake()).unwrap();
        assert_eq!(p.entry["door"]["admit"], json!(["node-b"]));
        assert!(crate::node_workloads::validate_desired_entry(&p.entry, "node-a").is_err(), "another agent's CN is refused");
    }

    #[test]
    fn the_needs_carry_the_operators_controller_opt_in() {
        let (d, raw) = decl();
        let mut b = body();
        b.on_controller = true;
        assert!(plan("rhaddon", &d, &raw, "node-a", &node(), &b, &fake()).unwrap().needs.on_controller);
        assert!(!plan("rhaddon", &d, &raw, "node-a", &node(), &body(), &fake()).unwrap().needs.on_controller);
    }

    #[test]
    fn refusal_statuses_split_the_requests_fault_from_the_nodes() {
        for c in [code::SET_MISSING, code::SET_SLOT_INVALID, code::PROFILE_INVALID, code::ENV_OUT_OF_BOUNDS, code::DESIRED_INVALID] {
            assert_eq!(refusal_status(c), StatusCode::BAD_REQUEST, "{c}");
        }
        for c in [code::CONSENT_NONE, code::DISK, code::IMAGE_MISSING, code::SET_UNVERIFIED, code::DOOR_UNREACHABLE, code::CONTROLLER_HOST] {
            assert_eq!(refusal_status(c), StatusCode::CONFLICT, "{c}");
        }
    }
}
