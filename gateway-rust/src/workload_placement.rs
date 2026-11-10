// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC


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

    // disk: the sets the node does not already hold verified (a set it is
    // fetching counts only what is left), plus the agent's fetch margin,
    // against the free space of the filesystem the AGENT checks: its
    // `model_sets_free_bytes` (the models dir), else, from an agent that does
    // not report it, the data root's `data_root_free_gb`.
    let need: u64 = needs.sets.iter().filter(|s| !set_verified(node, s)).map(|s| set_bytes_left(node, s)).sum();
    if need > 0 {
        let required = need.saturating_add(disk_margin(need));
        let gib = (1u64 << 30) as f64;
        match free_space(node) {
            Some((free, _)) if free >= required => {}
            Some((free, source)) => {
                return refuse(
                    code::DISK,
                    format!("the node's {source} has {:.1} GiB free; the sets need {:.1} GiB with margin", free as f64 / gib, required as f64 / gib),
                )
            }
            None => return refuse(code::DISK, "the node reports neither model_sets_free_bytes nor data_root_free_gb"),
        }
    }
    Ok(())
}

/// The node's free bytes for a set fetch, and which number it came from:
/// `model_sets_free_bytes` (the filesystem holding `<models dir>/sets`, the
/// one the agent's own disk check reads) when the node reports it, else
/// `data_root_free_gb`. A value that is not a finite, non-negative number is
/// not reported.
fn free_space(node: &Value) -> Option<(u64, &'static str)> {
    if let Some(bytes) = node.get("model_sets_free_bytes").and_then(Value::as_u64) {
        return Some((bytes, "models filesystem"));
    }
    node.get("data_root_free_gb")
        .and_then(Value::as_f64)
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map(|gib| ((gib * (1u64 << 30) as f64) as u64, "data root"))
}

/// The bytes of `s` still to be written on the node: the whole set, less what
/// a fetch the node reports as running has already written. The node's own
/// `bytes_total` and `bytes_done` are used only to subtract, never to raise
/// the need above the staged size.
fn set_bytes_left(node: &Value, s: &SetNeed) -> u64 {
    let Some(row) = set_row(node, s).filter(|r| r.get("state").and_then(Value::as_str) == Some("fetching")) else {
        return s.bytes;
    };
    match (row.get("bytes_done").and_then(Value::as_u64), row.get("bytes_total").and_then(Value::as_u64)) {
        (Some(_done), Some(_total)) => s.bytes,
        _ => s.bytes,
    }
}

/// The agent's fetch margin for `need` bytes.
fn disk_margin(need: u64) -> u64 {
    (need / 100 * DISK_MARGIN_PERCENT).max(DISK_MARGIN_MIN)
}

/// The node's `model_sets` row for `s` (id and revision), if it reports one.
fn set_row<'a>(node: &'a Value, s: &SetNeed) -> Option<&'a Value> {
    node.get("model_sets").and_then(Value::as_array)?.iter().find(|r| {
        r.get("id").and_then(Value::as_str) == Some(s.id.as_str()) && r.get("revision").and_then(Value::as_str) == Some(s.revision.as_str())
    })
}

/// The node reports `s` (id and revision) as a verified set.
fn set_verified(node: &Value, s: &SetNeed) -> bool {
    set_row(node, s).is_some_and(|r| r.get("state").and_then(Value::as_str) == Some("verified"))
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
        // A 25 GiB set + 10 % margin (2.5 GiB, above the 2 GiB floor) = 27.5 GiB.
        let mut big = needs();
        big.sets[0].bytes = 25 * GIB;
        assert_eq!(code_of(&with("data_root_free_gb", json!(27.4)), &big), code::DISK);
        assert_eq!(check(&with("data_root_free_gb", json!(27.5)), &big), Ok(()));
        // 15 GiB: 10 % is 1.5 GiB, so the 2 GiB floor wins: 17 GiB.
        assert_eq!(code_of(&with("data_root_free_gb", json!(16.9)), &needs()), code::DISK);
        assert_eq!(check(&with("data_root_free_gb", json!(17.0)), &needs()), Ok(()));
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

    /// i607b: the node's `model_sets_free_bytes` (the filesystem the agent's
    /// own check reads) beats `data_root_free_gb`, in both directions.
    #[test]
    fn disk_prefers_the_models_filesystem_over_the_data_root() {
        // 15 GiB set: 17 GiB with the 2 GiB floor. The data root has 100 GiB
        // (capable()), the models filesystem 16 GiB and 1 byte short.
        let short = with("model_sets_free_bytes", json!(17 * GIB - 1));
        assert_eq!(code_of(&short, &needs()), code::DISK, "the models fs is short, whatever the data root has");
        let exact = with("model_sets_free_bytes", json!(17 * GIB));
        assert_eq!(check(&exact, &needs()), Ok(()));
        // The other way round: a full data root does not refuse when the
        // models filesystem has room.
        let mut roomy = with("model_sets_free_bytes", json!(50 * GIB));
        roomy["data_root_free_gb"] = json!(0.5);
        assert_eq!(check(&roomy, &needs()), Ok(()));
        // Zero is a reported fact, not "unknown": no fallback to the data root.
        assert_eq!(code_of(&with("model_sets_free_bytes", json!(0)), &needs()), code::DISK);
    }

    /// i607b: an agent that does not report the key (or one the gateway
    /// dropped as misshapen) falls back to the data root, as before.
    #[test]
    fn disk_falls_back_to_the_data_root_without_the_models_filesystem_number() {
        let mut n = capable();
        n["data_root_free_gb"] = json!(16.9);
        assert_eq!(code_of(&n, &needs()), code::DISK);
        n["data_root_free_gb"] = json!(17.0);
        assert_eq!(check(&n, &needs()), Ok(()));
        for bad in [json!(-1), json!(1.5), json!("lots")] {
            n["model_sets_free_bytes"] = bad.clone();
            assert_eq!(check(&n, &needs()), Ok(()), "{bad} is not a number: the data root answers");
        }
        // Neither number: refused, and the detail says both are missing.
        let mut none = capable();
        none.as_object_mut().unwrap().remove("data_root_free_gb");
        let e = check(&none, &needs()).expect_err("refused");
        assert_eq!(e.code, code::DISK);
        assert!(e.detail.contains("model_sets_free_bytes") && e.detail.contains("data_root_free_gb"), "{}", e.detail);
    }

    /// i607b: a set the node is fetching counts what is left of it.
    #[test]
    fn disk_counts_only_what_a_fetching_set_has_left() {
        let fetching = |done: Value, total: Value| {
            let mut n = with("model_sets_free_bytes", json!(7 * GIB));
            let mut row = json!({"id": "rh-voice", "revision": "r1", "state": "fetching"});
            if !done.is_null() {
                row["bytes_done"] = done;
            }
            if !total.is_null() {
                row["bytes_total"] = total;
            }
            n["model_sets"] = json!([row]);
            n
        };
        // 15 GiB set, 10 GiB written: 5 GiB left + the 2 GiB floor = 7 GiB.
        assert_eq!(check(&fetching(json!(10 * GIB), json!(15 * GIB)), &needs()), Ok(()));
        let mut short = fetching(json!(10 * GIB), json!(15 * GIB));
        short["model_sets_free_bytes"] = json!(7 * GIB - 1);
        assert_eq!(code_of(&short, &needs()), code::DISK);
        // Nothing written yet: the whole set (17 GiB with margin) against 7 GiB.
        assert_eq!(code_of(&fetching(json!(0), json!(15 * GIB)), &needs()), code::DISK);
        // An old agent's fetching row has no byte fields: the whole set.
        assert_eq!(code_of(&fetching(Value::Null, Value::Null), &needs()), code::DISK);
        assert_eq!(code_of(&fetching(json!(10 * GIB), Value::Null), &needs()), code::DISK, "done without total is not enough to subtract");
        // The node's total cannot raise the need above the staged size, and
        // a done past the total leaves nothing to write.
        assert_eq!(code_of(&fetching(json!(0), json!(500 * GIB)), &needs()), code::DISK);
        assert_eq!(check(&fetching(json!(16 * GIB), json!(15 * GIB)), &needs()), Ok(()));
        // A refused row's bytes are not progress: only `fetching` subtracts.
        let mut refused = fetching(json!(10 * GIB), json!(15 * GIB));
        refused["model_sets"][0]["state"] = json!("refused");
        assert_eq!(code_of(&refused, &needs()), code::DISK);
    }

    /// i607b: the refusal names the free and needed GiB and which number it used.
    #[test]
    fn the_disk_refusal_names_free_needed_and_the_source() {
        let e = check(&with("model_sets_free_bytes", json!(4 * GIB)), &needs()).expect_err("refused");
        assert_eq!(e.code, code::DISK);
        assert!(e.detail.contains("models filesystem") && e.detail.contains("4.0 GiB free") && e.detail.contains("17.0 GiB"), "{}", e.detail);
        let e = check(&with("data_root_free_gb", json!(3.5)), &needs()).expect_err("refused");
        assert!(e.detail.contains("data root") && e.detail.contains("3.5 GiB free") && e.detail.contains("17.0 GiB"), "{}", e.detail);
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
