// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Wired in by the workload placement route (i300 H3b); until then only its
// tests call it.
#![allow(dead_code)]

//! The hard filters of an add-on node-workload placement (i300 H3,
//! `docs/reference/node-workloads.md` "Reasons"): refusals, never preferences.
//!
//! [`check`] reads the node's STORED heartbeat row (the `mesh_nodes` record the
//! A4 keys land in, `routes/cluster.rs` `carry_i300`) and what the placement
//! needs, and returns the first refusal. Each code is the agent's own reason,
//! spelled identically, so a placement the gateway accepts is one the agent
//! would not refuse for the same fact.
//!
//! ## Unknown facts
//!
//! The agent OMITS a fact it cannot establish (the i495 rule). Placement is
//! strict (`--node`, no pool fallback), so an omitted fact the placement
//! depends on is a refusal with that fact's code and a detail that says it was
//! not reported, never a pass. One exception, `nvidia_driver_caps_ok`: the
//! 0.6.18 agent never reports it (no sound probe exists,
//! `node-agent-go/internal/nodepolicy/facts.go`), so only an explicit `false`
//! refuses; silence would otherwise refuse every GPU node.
//!
//! ## Order
//!
//! door (os), arch, consent, controller host, nvidia runtime, driver caps,
//! compute capability, disk. The first failing rule wins.

use serde_json::Value;

use crate::node_workloads::{code, compute_cap_at_least};

/// The free space a set fetch keeps beyond its bytes: 10 % of them, at least
/// 2 GiB. The agent's `modelsets.DiskMarginPercent` / `DiskMarginMin`.
pub const DISK_MARGIN_MIN: u64 = 2 << 30;
pub const DISK_MARGIN_PERCENT: u64 = 10;

/// One model set the workload's slots name, with its total file bytes.
#[derive(Debug, Clone)]
pub struct SetNeed {
    pub id: String,
    pub revision: String,
    pub bytes: u64,
}

/// What a workload placement needs of its node.
#[derive(Debug, Clone)]
pub struct Needs {
    pub addon: String,
    /// The worker image's lock digest (`sha256:<hex>`): what approvals name.
    pub digest: String,
    /// `accel.gpu` of the declaration.
    pub gpu: u32,
    /// The chosen profile's `min_compute`, when it has one.
    pub min_compute: Option<String>,
    /// The main set's `needs.arch` (`amd64`, `arm64`); empty = any.
    pub arch: Vec<String>,
    pub sets: Vec<SetNeed>,
    /// The operator opted in to node workloads on the controller's host for
    /// this placement (D4; the agent still applies its own opt-in).
    pub on_controller: bool,
}

/// A refusal: the agent's reason code and a sentence for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub detail: String,
}

fn refuse(code: &'static str, detail: impl Into<String>) -> Result<(), Refusal> {
    Err(Refusal { code, detail: detail.into() })
}

/// The first hard filter `node` fails for `needs`, or `Ok(())`.
pub fn check(node: &Value, needs: &Needs) -> Result<(), Refusal> {
    // door: the door is on an internal Docker bridge, which only Linux routes
    // to (A9).
    match node.get("os").and_then(Value::as_str) {
        Some("linux") => {}
        Some(os) => return refuse(code::DOOR_UNREACHABLE, format!("the node runs {os}; a node workload's door needs Linux")),
        None => return refuse(code::DOOR_UNREACHABLE, "the node does not report its os (an agent older than 0.6.18)"),
    }

    // arch: the main set's needs.arch, against the agent's runtime.GOARCH.
    if !needs.arch.is_empty() {
        let arch = node.pointer("/capabilities/arch").or_else(|| node.get("arch")).and_then(Value::as_str);
        match arch {
            Some(a) if needs.arch.iter().any(|w| w == a) => {}
            Some(a) => return refuse(code::ARCH_MISMATCH, format!("the node is {a}; the set needs {}", needs.arch.join(" or "))),
            None => return refuse(code::ARCH_MISMATCH, "the node does not report its arch"),
        }
    }

    // consent: the node owner's policy, and per-digest approval under approve.
    match node.get("addon_workloads_policy").and_then(Value::as_str) {
        Some("auto") => {}
        Some("approve") => {
            let Some(list) = node.get("addon_workloads_approvals").and_then(Value::as_array) else {
                return refuse(code::CONSENT_UNAPPROVED, "the node does not report its approvals");
            };
            let approved = list.iter().any(|a| {
                a.get("addon").and_then(Value::as_str) == Some(needs.addon.as_str())
                    && a.get("digest").and_then(Value::as_str) == Some(needs.digest.as_str())
            });
            if !approved {
                return refuse(code::CONSENT_UNAPPROVED, format!("{} at {} is not approved on the node", needs.addon, needs.digest));
            }
        }
        Some(_) => return refuse(code::CONSENT_NONE, "the node's addon_workloads_policy is none"),
        None => return refuse(code::CONSENT_NONE, "the node does not report its addon_workloads_policy"),
    }

    // controller host (D4): refused unless the operator opted in.
    if !needs.on_controller {
        match node.get("controller_host").and_then(Value::as_bool) {
            Some(false) => {}
            Some(true) => return refuse(code::CONTROLLER_HOST, "the node is the controller's host; opt in to place a node workload there"),
            None => return refuse(code::CONTROLLER_HOST, "the node does not report whether it is the controller's host"),
        }
    }

    if needs.gpu > 0 {
        // nvidia runtime registered with docker.
        match node.get("nvidia_runtime").and_then(Value::as_bool) {
            Some(true) => {}
            Some(false) => return refuse(code::NVIDIA_RUNTIME_MISSING, "the nvidia container runtime is not registered on the node"),
            None => return refuse(code::NVIDIA_RUNTIME_MISSING, "the node does not report its nvidia runtime"),
        }

        // driver caps: only an explicit false refuses (see the module doc).
        if node.get("nvidia_driver_caps_ok").and_then(Value::as_bool) == Some(false) {
            return refuse(code::DRIVER_CAPS_MISSING, "the node's driver cannot grant compute,utility");
        }

        // compute capability, compared numerically; unparsable is unknown.
        if let Some(min) = needs.min_compute.as_deref() {
            let have = node.get("gpu_compute_cap").and_then(Value::as_str);
            match have.and_then(|h| compute_cap_at_least(h, min)) {
                Some(true) => {}
                Some(false) => {
                    return refuse(code::COMPUTE_CAP_LOW, format!("the node's GPU is compute capability {}; the profile needs {min}", have.unwrap_or("?")))
                }
                None => return refuse(code::COMPUTE_CAP_LOW, format!("the node's compute capability is unknown; the profile needs {min}")),
            }
        }
    }

    // disk: the sets the node does not already hold verified, plus the
    // agent's fetch margin, against the data root's free space.
    let need: u64 = needs.sets.iter().filter(|s| !set_verified(node, s)).map(|s| s.bytes).sum();
    if need > 0 {
        let required = need.saturating_add(disk_margin(need));
        match node.get("data_root_free_gb").and_then(Value::as_f64).filter(|v| v.is_finite() && *v >= 0.0) {
            Some(gib) if gib * (1u64 << 30) as f64 >= required as f64 => {}
            Some(gib) => {
                return refuse(code::DISK, format!("the node's data root has {gib:.1} GiB free; the sets need {:.1} GiB with margin", required as f64 / (1u64 << 30) as f64))
            }
            None => return refuse(code::DISK, "the node does not report its data root's free space"),
        }
    }
    Ok(())
}

/// The agent's fetch margin for `need` bytes.
fn disk_margin(need: u64) -> u64 {
    (need / 100 * DISK_MARGIN_PERCENT).max(DISK_MARGIN_MIN)
}

/// The node reports `s` (id and revision) as a verified set.
fn set_verified(node: &Value, s: &SetNeed) -> bool {
    node.get("model_sets").and_then(Value::as_array).is_some_and(|rows| {
        rows.iter().any(|r| {
            r.get("id").and_then(Value::as_str) == Some(s.id.as_str())
                && r.get("revision").and_then(Value::as_str) == Some(s.revision.as_str())
                && r.get("state").and_then(Value::as_str) == Some("verified")
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const GIB: u64 = 1 << 30;

    /// A node every filter admits: Linux amd64, approve with this add-on and
    /// digest approved, not the controller's host, nvidia runtime, caps ok,
    /// compute 8.6, 100 GiB free.
    fn capable() -> Value {
        json!({
            "id": "n1", "os": "linux", "capabilities": {"arch": "amd64"},
            "addon_workloads_policy": "approve",
            "addon_workloads_approvals": [{"addon": "rhaddon", "digest": DIGEST}],
            "controller_host": false,
            "nvidia_runtime": true, "nvidia_driver_caps_ok": true,
            "gpu_compute_cap": "8.6",
            "data_root_free_gb": 100.0,
            "model_sets": [],
        })
    }

    fn needs() -> Needs {
        Needs {
            addon: "rhaddon".into(),
            digest: DIGEST.into(),
            gpu: 1,
            min_compute: Some("8.0".into()),
            arch: vec!["amd64".into()],
            sets: vec![SetNeed { id: "rh-voice".into(), revision: "r1".into(), bytes: 15 * GIB }],
            on_controller: false,
        }
    }

    fn with(k: &str, v: Value) -> Value {
        let mut n = capable();
        n[k] = v;
        n
    }

    fn without(k: &str) -> Value {
        let mut n = capable();
        n.as_object_mut().unwrap().remove(k);
        n
    }

    fn code_of(node: &Value, n: &Needs) -> &'static str {
        check(node, n).expect_err("refused").code
    }

    #[test]
    fn a_capable_node_passes_every_filter() {
        assert_eq!(check(&capable(), &needs()), Ok(()));
        let mut auto = capable();
        auto["addon_workloads_policy"] = json!("auto");
        auto.as_object_mut().unwrap().remove("addon_workloads_approvals");
        assert_eq!(check(&auto, &needs()), Ok(()), "auto needs no approval");
    }

    #[test]
    fn door_unreachable_off_linux_or_unreported() {
        assert_eq!(code_of(&with("os", json!("darwin")), &needs()), code::DOOR_UNREACHABLE);
        assert_eq!(code_of(&with("os", json!("windows")), &needs()), code::DOOR_UNREACHABLE);
        assert_eq!(code_of(&without("os"), &needs()), code::DOOR_UNREACHABLE);
    }

    #[test]
    fn arch_mismatch_off_the_sets_arch_or_unreported() {
        assert_eq!(code_of(&with("capabilities", json!({"arch": "arm64"})), &needs()), code::ARCH_MISMATCH);
        assert_eq!(code_of(&with("capabilities", json!({})), &needs()), code::ARCH_MISMATCH);
        let mut any = needs();
        any.arch.clear();
        assert_eq!(check(&with("capabilities", json!({"arch": "arm64"})), &any), Ok(()), "no needs.arch: any arch");
        let mut both = needs();
        both.arch = vec!["arm64".into(), "amd64".into()];
        assert_eq!(check(&capable(), &both), Ok(()));
    }

    #[test]
    fn consent_none_unless_the_node_says_approve_or_auto() {
        assert_eq!(code_of(&with("addon_workloads_policy", json!("none")), &needs()), code::CONSENT_NONE);
        assert_eq!(code_of(&with("addon_workloads_policy", json!("always")), &needs()), code::CONSENT_NONE);
        assert_eq!(code_of(&without("addon_workloads_policy"), &needs()), code::CONSENT_NONE);
    }

    #[test]
    fn consent_unapproved_needs_this_addon_at_this_digest() {
        let other_digest = format!("sha256:{}", "b".repeat(64));
        assert_eq!(
            code_of(&with("addon_workloads_approvals", json!([{"addon": "rhaddon", "digest": other_digest}])), &needs()),
            code::CONSENT_UNAPPROVED,
            "an approval of another digest is not this one's"
        );
        assert_eq!(
            code_of(&with("addon_workloads_approvals", json!([{"addon": "otheraddon", "digest": DIGEST}])), &needs()),
            code::CONSENT_UNAPPROVED
        );
        assert_eq!(code_of(&with("addon_workloads_approvals", json!([])), &needs()), code::CONSENT_UNAPPROVED);
        assert_eq!(code_of(&without("addon_workloads_approvals"), &needs()), code::CONSENT_UNAPPROVED);
    }

    #[test]
    fn controller_host_refused_unless_the_operator_opts_in() {
        assert_eq!(code_of(&with("controller_host", json!(true)), &needs()), code::CONTROLLER_HOST);
        assert_eq!(code_of(&without("controller_host"), &needs()), code::CONTROLLER_HOST);
        let mut opted = needs();
        opted.on_controller = true;
        assert_eq!(check(&with("controller_host", json!(true)), &opted), Ok(()));
    }

    #[test]
    fn nvidia_runtime_missing_for_a_gpu_workload() {
        assert_eq!(code_of(&with("nvidia_runtime", json!(false)), &needs()), code::NVIDIA_RUNTIME_MISSING);
        assert_eq!(code_of(&without("nvidia_runtime"), &needs()), code::NVIDIA_RUNTIME_MISSING);
        let mut cpu = needs();
        cpu.gpu = 0;
        assert_eq!(check(&with("nvidia_runtime", json!(false)), &cpu), Ok(()), "a CPU workload needs no runtime");
    }

    #[test]
    fn driver_caps_missing_only_on_an_explicit_false() {
        assert_eq!(code_of(&with("nvidia_driver_caps_ok", json!(false)), &needs()), code::DRIVER_CAPS_MISSING);
        assert_eq!(check(&without("nvidia_driver_caps_ok"), &needs()), Ok(()), "the 0.6.18 agent never reports it");
    }

    #[test]
    fn compute_cap_low_numerically_and_when_unknown() {
        assert_eq!(code_of(&with("gpu_compute_cap", json!("7.5")), &needs()), code::COMPUTE_CAP_LOW);
        assert_eq!(code_of(&without("gpu_compute_cap"), &needs()), code::COMPUTE_CAP_LOW);
        assert_eq!(code_of(&with("gpu_compute_cap", json!("eight")), &needs()), code::COMPUTE_CAP_LOW, "unparsable is unknown, not a pass");
        let mut n10 = needs();
        n10.min_compute = Some("8.9".into());
        assert_eq!(check(&with("gpu_compute_cap", json!("10.0")), &n10), Ok(()), "10.0 is above 8.9 as numbers");
        assert_eq!(code_of(&with("gpu_compute_cap", json!("8.10")), &{
            let mut m = needs();
            m.min_compute = Some("8.11".into());
            m
        }), code::COMPUTE_CAP_LOW);
    }

    #[test]
    fn disk_counts_unheld_sets_plus_the_agents_margin() {
        // 15 GiB set + 10 % margin (1.5 GiB) = 16.5 GiB.
        assert_eq!(code_of(&with("data_root_free_gb", json!(16.4)), &needs()), code::DISK);
        assert_eq!(check(&with("data_root_free_gb", json!(16.5)), &needs()), Ok(()));
        assert_eq!(code_of(&without("data_root_free_gb"), &needs()), code::DISK);
        // A small set still keeps the 2 GiB floor.
        let mut small = needs();
        small.sets[0].bytes = GIB;
        assert_eq!(code_of(&with("data_root_free_gb", json!(2.9)), &small), code::DISK);
        // A set the node already holds verified needs no space.
        let mut held = with("data_root_free_gb", json!(0.5));
        held["model_sets"] = json!([{"id": "rh-voice", "revision": "r1", "state": "verified"}]);
        assert_eq!(check(&held, &needs()), Ok(()));
        held["model_sets"] = json!([{"id": "rh-voice", "revision": "r1", "state": "fetching"}]);
        assert_eq!(code_of(&held, &needs()), code::DISK, "a set still fetching is not held");
    }

    #[test]
    fn the_first_failing_rule_wins_in_order() {
        let mut n = with("os", json!("darwin"));
        n["addon_workloads_policy"] = json!("none");
        assert_eq!(code_of(&n, &needs()), code::DOOR_UNREACHABLE);
        let mut n = with("addon_workloads_policy", json!("none"));
        n["nvidia_runtime"] = json!(false);
        assert_eq!(code_of(&n, &needs()), code::CONSENT_NONE);
    }

    #[test]
    fn every_code_here_is_an_agent_reason() {
        for c in [
            code::DOOR_UNREACHABLE, code::ARCH_MISMATCH, code::CONSENT_NONE, code::CONSENT_UNAPPROVED,
            code::CONTROLLER_HOST, code::NVIDIA_RUNTIME_MISSING, code::DRIVER_CAPS_MISSING,
            code::COMPUTE_CAP_LOW, code::DISK,
        ] {
            assert!(code::REASONS.contains(&c), "{c} is not in the agent's reason list");
        }
    }
}
