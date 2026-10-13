// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The node tier ladder — one classifier, several wire shapes.
//!
//! Tier decides `slots_for_tier` (`scheduler_slots.rs`), placement, and
//! whether `CompanionPolicy` gates a node at all. Until now it was decided
//! ONCE, at birth, and frozen into `NODE_TIER` in the agent's env; the agent
//! reports `Tier: cfg.Tier` and computes nothing. Add a GPU, move a disk into
//! different hardware, or reinstall an agent without re-provisioning, and the
//! node keeps asserting a class it no longer has. A stale tier misroutes work
//! rather than failing.
//!
//! ## Why the ladder lives HERE
//!
//! It had two homes in `noo-cli` (`derive_tier_facts` over the enrolment JSON,
//! `derive_tier` over `noo-gate facts` text) — the same rules behind two
//! parsers. This adds the one the gateway needs, and puts the canonical
//! statement of the rules beside their consumers: `slots_for_tier` and
//! `normalize_tier` are in this crate, and only this crate sees a heartbeat.
//! The CLI's two remain because they run at BIRTH, before a controller has
//! ever heard of the node — `noo enroll` classifies with no round-trip.
//!
//! The two crates share no library (separate `Cargo.toml`s, no workspace, no
//! path dependency, separate Docker build contexts — `cargo-docker.sh` mounts
//! only the crate, so neither can even `include_str!` a file above its own
//! root), so the two are bound two ways instead of by a shared function:
//!
//! * `fixtures/node_tier_cases.json` — the behavioural corpus. Every case
//!   states inputs and the tier this ladder must produce; the tests below run
//!   all of them.
//! * `tests/test_node_tier_ladder_parity.py` — parses THIS file and
//!   `provision.rs` and fails when the board list, the thresholds or the
//!   precedence stop matching. Textual, like `test_job_type_declarations.py`,
//!   and for the same reason: no compiler spans both crates.
//!
//! ## Unknown is not a tier
//!
//! [`derive`] returns [`TierVerdict::Unknown`] when the reported facts cannot
//! decide, and callers must not substitute a default. The CLI ladders
//! `unwrap_or` their way to `"3"` because at birth the enrolling script always
//! sends every field — an absent one there means the probe genuinely found
//! nothing. On the heartbeat path absence means something else entirely: an
//! older agent build, a capability map that has not arrived yet, a partial
//! payload. Deriving `3` from that and comparing it against a declared `1`
//! manufactures a disagreement out of silence, and this file exists to act on
//! disagreements.
//!
//! ## Tiers 5 and 6 are roles, not hardware
//!
//! A phone and a Pi-with-webcam classify identically on hardware; tier 5 means
//! "sensor proxy, zero scheduler slots" and tier 6 means "probes only". Both
//! are operator declarations about PURPOSE. Derivation covers 1–4 and never
//! emits 5 or 6; callers must also refuse to re-tier a node that declares one.

use serde_json::Value;

/// The facts the ladder needs, normalised out of whatever wire shape carried
/// them. Every field is optional because every field can genuinely be absent,
/// and the difference between "absent" and "zero" is the point.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct TierFacts {
    /// Raw `/proc/device-tree/model`. Present only on ARM SBCs.
    pub device_tree_model: Option<String>,
    /// `None` when the architecture was not reported — not "assume x86".
    pub is_arm: Option<bool>,
    /// Whether a GPU is present at all. On the heartbeat path this is derived
    /// from a reported VRAM figure; at enrolment it is a direct probe.
    pub gpu_present: Option<bool>,
    /// The GPU's memory in GB — discrete VRAM, or the usable share of system
    /// RAM on a unified-memory box.
    pub gpu_memory_gb: Option<f64>,
    pub unified_memory: Option<bool>,
    /// `cuda` | `metal` | `none`. Decides whether a unified-memory box can
    /// reach tier 1 at all: there is no vLLM on Metal.
    pub gpu_api: Option<String>,
}

/// What the ladder concluded.
#[derive(Debug, Clone, PartialEq)]
pub enum TierVerdict {
    Derived {
        tier: i64,
        /// Why, in the ladder's own terms. Carried so a misclassification is
        /// arguable from a log line instead of discovered as an
        /// `UPDATE cluster_nodes` months later.
        reason: String,
    },
    /// Not enough was reported to classify. Callers compare nothing and act on
    /// nothing.
    Unknown { why: String },
}

impl TierVerdict {
    pub fn tier(&self) -> Option<i64> {
        match self {
            TierVerdict::Derived { tier, .. } => Some(*tier),
            TierVerdict::Unknown { .. } => None,
        }
    }

    pub fn explain(&self) -> &str {
        match self {
            TierVerdict::Derived { reason, .. } => reason,
            TierVerdict::Unknown { why } => why,
        }
    }
}

/// Board model substrings that mean "this is an edge device".
///
/// Kept identical to the CLI's list. The fixture corpus is what actually holds
/// them together; this constant is where a new board gets added first.
const SBC_MODELS: &[&str] = &["raspberry", "jetson", "orangepi", "orange pi", "rock"];

fn model_is_sbc(model: &str) -> bool {
    let m = model.to_lowercase();
    SBC_MODELS.iter().any(|s| m.contains(s))
}

/// Classify, or decline to.
///
/// Precedence, and the order is load-bearing:
///
/// 1. **Unified memory** — Apple Silicon, Tegra, GB10. The GPU draws on system
///    RAM, so a discrete-VRAM reading of 0 is not "no GPU". Tier 1 only on
///    CUDA (no vLLM on Metal), so an 8 GB Mac mini is tier 2, not edge.
/// 2. **Device-tree model** — before the GPU rules, deliberately. A Jetson
///    reports VRAM > 0 and is still edge-class; a VRAM-first ladder gives it
///    two slots of vLLM work it cannot run.
/// 3. **A discrete GPU** — tier 2. Tier 1 is controller-class and is never
///    auto-assigned from a bare GPU-present signal, which is what the enrolment
///    ladder has always done.
/// 4. **aarch64** with no recognised board — edge by architecture.
/// 5. Otherwise a CPU worker.
pub fn derive(f: &TierFacts) -> TierVerdict {
    if f.unified_memory == Some(true) {
        // A unified-memory box that did not report its usable share tells us
        // nothing: the whole point of the branch is the size of that share.
        let Some(usable) = f.gpu_memory_gb else {
            return TierVerdict::Unknown {
                why: "unified memory reported without a usable-GPU figure".into(),
            };
        };
        let api = f.gpu_api.as_deref().unwrap_or("");
        if usable >= 10.0 && api == "cuda" {
            return TierVerdict::Derived {
                tier: 1,
                reason: format!("unified memory, {usable:.1} GB usable on CUDA (>= 10 GB)"),
            };
        }
        if usable >= 4.0 {
            let via = if api.is_empty() { "unknown API" } else { api };
            return TierVerdict::Derived {
                tier: 2,
                reason: format!("unified memory, {usable:.1} GB usable via {via} (no vLLM off CUDA)"),
            };
        }
        return TierVerdict::Derived {
            tier: 4,
            reason: format!("unified memory with only {usable:.1} GB usable (< 4 GB)"),
        };
    }

    if let Some(model) = f.device_tree_model.as_deref().filter(|m| !m.trim().is_empty()) {
        if model_is_sbc(model) {
            return TierVerdict::Derived {
                tier: 4,
                reason: format!("SBC via /proc/device-tree/model (\"{}\")", model.trim()),
            };
        }
    }

    if f.gpu_present == Some(true) {
        let size = f
            .gpu_memory_gb
            .map(|g| format!("{g:.1} GB"))
            .unwrap_or_else(|| "size not reported".into());
        return TierVerdict::Derived {
            tier: 2,
            reason: format!(
                "discrete GPU present ({size}); tier 1 is controller-class and never auto-assigned"
            ),
        };
    }

    match f.is_arm {
        Some(true) => TierVerdict::Derived {
            tier: 4,
            reason: "aarch64 with no recognised board model — edge by architecture".into(),
        },
        Some(false) => TierVerdict::Derived {
            tier: 3,
            reason: "x86 with no GPU signal — CPU worker".into(),
        },
        // Nothing usable arrived. Not tier 3: see the module header.
        None => TierVerdict::Unknown {
            why: "no architecture, board model or GPU signal reported".into(),
        },
    }
}

/// Read the ladder's inputs out of a heartbeat `capabilities` object.
///
/// The Go agent's field names (`hardware.Capabilities`), which are NOT the
/// enrolment facts' names — `vram_gb` here, `usable_gpu_gb` there. Two shapes
/// is why the ladder takes a struct instead of a `&Value`.
///
/// `gpu_present` is derived from a positive VRAM figure rather than read: the
/// agent reports `gpu_model` even on hardware that has none (a stale
/// `GPU_MODEL` env copied during provisioning put a laptop's RTX 3080 on a
/// Raspberry Pi), which is the same reason `clamp_gpu_model` exists on the
/// heartbeat path.
pub fn facts_from_capabilities(caps: &Value) -> TierFacts {
    let f = |k: &str| caps.get(k);
    let vram = f("vram_gb").and_then(|v| v.as_f64());
    TierFacts {
        device_tree_model: f("device_tree_model")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|s| !s.trim().is_empty()),
        is_arm: arch_is_arm(caps),
        // Only a positive reading is evidence. `Some(false)` on a zero would
        // assert "no GPU" from a field an older agent simply omits, so the
        // absent case stays absent.
        gpu_present: vram.map(|v| v > 0.0),
        gpu_memory_gb: vram.filter(|v| *v > 0.0),
        unified_memory: f("unified_memory").and_then(|v| v.as_bool()),
        gpu_api: f("gpu_api").and_then(|v| v.as_str()).map(str::to_string),
    }
}

/// Architecture from a capabilities map. Mirrors `routes::cluster::arch_is_arm`
/// — an unrecognised value yields `None`, never a guess.
fn arch_is_arm(caps: &Value) -> Option<bool> {
    if let Some(a) = caps.get("arch").and_then(|v| v.as_str()) {
        match a.trim().to_ascii_lowercase().as_str() {
            "arm64" | "aarch64" | "arm" | "armv6l" | "armv7l" | "armhf" | "armel" => {
                return Some(true)
            }
            "amd64" | "x86_64" | "x64" | "x86" | "i386" | "i686" => return Some(false),
            _ => {}
        }
    }
    caps.get("is_arm").and_then(|v| v.as_bool())
}

/// Tiers that describe a ROLE the operator chose, which no hardware reading
/// may overrule.
pub fn is_role_tier(tier: i64) -> bool {
    tier == 5 || tier == 6
}

/// The shared corpus every implementation of the ladder is checked against.
///
/// Embedded so the gateway's own tests do not depend on a file path at
/// runtime; `tests/test_node_tier_ladder_parity.py` proves this is the same
/// file the CLI reads.
#[cfg(test)]
const FIXTURES: &str = include_str!("../fixtures/node_tier_cases.json");

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_shared_fixture_case_classifies_as_declared() {
        // The corpus is the contract between this ladder and the CLI's two.
        // A case added here that either side cannot satisfy is drift caught at
        // `cargo test` rather than on a node.
        let cases: Value = serde_json::from_str(FIXTURES).expect("fixture corpus parses");
        let arr = cases["cases"].as_array().expect("cases array");
        assert!(arr.len() >= 8, "corpus too thin to be a contract");
        for c in arr {
            let name = c["name"].as_str().unwrap_or("<unnamed>");
            let facts = TierFacts {
                device_tree_model: c["facts"]["device_tree_model"]
                    .as_str()
                    .map(str::to_string),
                is_arm: c["facts"]["is_arm"].as_bool(),
                gpu_present: c["facts"]["gpu_present"].as_bool(),
                gpu_memory_gb: c["facts"]["gpu_memory_gb"].as_f64(),
                unified_memory: c["facts"]["unified_memory"].as_bool(),
                gpu_api: c["facts"]["gpu_api"].as_str().map(str::to_string),
            };
            let got = derive(&facts).tier();
            let want = c["tier"].as_i64();
            assert_eq!(got, want, "case `{name}`: expected {want:?}, got {got:?}");
        }
    }

    #[test]
    fn a_board_beats_a_gpu() {
        // The Jetson case, stated on its own because it is the whole reason
        // the device-tree branch runs before the GPU one.
        let jetson = TierFacts {
            device_tree_model: Some("NVIDIA Jetson Orin Nano".into()),
            is_arm: Some(true),
            gpu_present: Some(true),
            gpu_memory_gb: Some(16.0),
            ..Default::default()
        };
        assert_eq!(derive(&jetson).tier(), Some(4));
        assert!(derive(&jetson).explain().contains("device-tree"));
    }

    #[test]
    fn a_big_gpu_is_tier_two_not_tier_one() {
        // Tier 1 is controller-class. A probe or a derivation that promoted a
        // 24 GB workstation to tier 1 would hand it two vLLM slots the
        // enrolment ladder never intended it to have.
        let ws = TierFacts {
            is_arm: Some(false),
            gpu_present: Some(true),
            gpu_memory_gb: Some(24.0),
            ..Default::default()
        };
        assert_eq!(derive(&ws).tier(), Some(2));
    }

    #[test]
    fn silence_is_unknown_never_tier_three() {
        // The failure this whole module is shaped around: an empty capability
        // map deriving `3`, disagreeing with a declared `1`, and re-tiering a
        // working GPU node down to one slot.
        assert_eq!(derive(&TierFacts::default()).tier(), None);
        assert_eq!(
            facts_from_capabilities(&json!({})),
            TierFacts::default(),
            "an empty capability map must produce no facts, not false ones"
        );
        assert_eq!(derive(&facts_from_capabilities(&json!({}))).tier(), None);
    }

    #[test]
    fn zero_vram_is_not_a_gpu_and_absent_vram_is_not_zero() {
        // Two different absences. A node reporting vram_gb: 0 has told us it
        // has no GPU; a node that omitted the field has told us nothing, and
        // must not be read as "no GPU" — which on an x86 box is the difference
        // between tier 3 and Unknown.
        let reported_zero = facts_from_capabilities(&json!({"vram_gb": 0.0, "arch": "x86_64"}));
        assert_eq!(reported_zero.gpu_present, Some(false));
        assert_eq!(reported_zero.gpu_memory_gb, None, "0 GB is not a size");
        assert_eq!(derive(&reported_zero).tier(), Some(3));

        let omitted = facts_from_capabilities(&json!({"arch": "x86_64"}));
        assert_eq!(omitted.gpu_present, None);
        assert_eq!(derive(&omitted).tier(), Some(3), "arch alone still classifies");

        let nothing = facts_from_capabilities(&json!({"cpu_cores": 8}));
        assert_eq!(derive(&nothing).tier(), None);
    }

    #[test]
    fn unified_memory_needs_its_size_before_it_decides_anything() {
        // `unified_memory: true` with no usable figure is the one case where a
        // present flag still leaves us unable to answer. Falling through to
        // the GPU rules would classify a Mac by its absent discrete VRAM.
        let m = TierFacts {
            unified_memory: Some(true),
            is_arm: Some(true),
            ..Default::default()
        };
        assert_eq!(derive(&m).tier(), None);
        assert!(derive(&m).explain().contains("usable"));
    }

    #[test]
    fn metal_never_reaches_tier_one() {
        // No vLLM on macOS. A 64 GB Mac Studio is a capable tier 2, and
        // calling it tier 1 would earn it a second concurrent slot for a
        // backend it cannot run.
        let studio = TierFacts {
            unified_memory: Some(true),
            gpu_memory_gb: Some(48.0),
            gpu_api: Some("metal".into()),
            is_arm: Some(true),
            ..Default::default()
        };
        assert_eq!(derive(&studio).tier(), Some(2));

        let spark = TierFacts {
            unified_memory: Some(true),
            gpu_memory_gb: Some(48.0),
            gpu_api: Some("cuda".into()),
            is_arm: Some(true),
            ..Default::default()
        };
        assert_eq!(spark.gpu_api.as_deref(), Some("cuda"));
        assert_eq!(derive(&spark).tier(), Some(1));
    }

    #[test]
    fn derivation_never_emits_a_role_tier() {
        // 5 and 6 mean "sensor proxy" and "probes only" — decisions about
        // purpose that no hardware reading can make. If the ladder could emit
        // one, a companion would be re-tiered into schedulable work.
        let cases: Value = serde_json::from_str(FIXTURES).unwrap();
        for c in cases["cases"].as_array().unwrap() {
            if let Some(t) = c["tier"].as_i64() {
                assert!(!is_role_tier(t), "fixture `{}` derives a role tier", c["name"]);
            }
        }
        assert!(is_role_tier(5) && is_role_tier(6));
        assert!(!is_role_tier(4));
    }

    #[test]
    fn capabilities_adapter_reads_the_agents_field_names() {
        // Guards the shape, not the ladder: the Go agent sends `vram_gb` and
        // `device_tree_model`, while the enrolment facts say `usable_gpu_gb`
        // and `model`. Reading the wrong one yields a silent Unknown forever.
        let caps = json!({
            "arch": "arm64",
            "vram_gb": 16.0,
            "device_tree_model": "NVIDIA Jetson Orin Nano",
            "unified_memory": false,
            "gpu_api": "cuda",
        });
        let f = facts_from_capabilities(&caps);
        assert_eq!(f.is_arm, Some(true));
        assert_eq!(f.gpu_memory_gb, Some(16.0));
        assert_eq!(f.device_tree_model.as_deref(), Some("NVIDIA Jetson Orin Nano"));
        assert_eq!(derive(&f).tier(), Some(4), "board still wins");
    }
}
