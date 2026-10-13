// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Add-on presence + the degradation contract.
//!
//! Mesh's add-ons include **trellion** (the ML knowledge pack — the Python
//! container answering the `worker.*` knowledge subjects; opt-out, on by
//! default) and **evolve** (the prompt-skill evolution sidecar; opt-in). This
//! module is the ONE place the gateway asks "is the add-on supposed to be
//! here?", so a disabled add-on produces an instant, explicit refusal
//! everywhere instead of a NATS timeout that reads like an outage.
//!
//! Deliberately CONFIG-driven — the `addons:` map in noomesh.yaml (e.g.
//! `addons.trellion: true`), not an env var — and not probed: "the operator
//! turned it off" and "it is broken" must stay distinguishable — preflight
//! and the dependency watchdog own the second case.

/// One registered add-on. The table below is the
/// single place a new add-on declares itself: name (the `/health`
/// `addons.<name>` key), enable flag, default polarity, and the
/// operator-facing refusal message. The dispatch seam (a NATS subject
/// prefix or a proxy route) stays per-addon code — those are genuinely
/// different surfaces — but presence, polarity and messaging are table
/// rows, not per-addon function pairs.
pub struct Addon {
    pub name: &'static str,
    /// `true` = opt-out (enabled unless explicitly off — trellion's
    /// polarity); `false` = opt-in (disabled unless explicitly on —
    /// evolve's polarity).
    pub default_on: bool,
    pub disabled_msg: &'static str,
    /// The entitlement feature this add-on needs, or `None` for the open
    /// ones. Features are the only authority; tiers are labels.
    pub requires_feature: Option<&'static str>,
    /// The refusal when the flag is on but the licence does not grant the
    /// feature. Empty for open add-ons.
    pub unlicensed_msg: &'static str,
    /// An HTTP add-on that ships its own route manifest. When the switch is
    /// on, the gateway reads it at startup from
    /// `addon_proxy::ROUTES_DIR/<name>/routes.json` (delivered read-only by
    /// the add-on's overlay) and refuses the add-on's routes, loudly, if it
    /// is missing or invalid. `false` for NATS add-ons: nothing is read.
    pub routes_manifest: bool,
}

pub const ADDONS: &[Addon] = &[
    Addon {
        name: "trellion",
        default_on: true,
        disabled_msg: DISABLED_MSG,
        requires_feature: None,
        unlicensed_msg: "",
        routes_manifest: false,
    },
    Addon {
        name: "evolve",
        default_on: false,
        disabled_msg: EVOLVE_DISABLED_MSG,
        requires_feature: Some("evolve"),
        unlicensed_msg: EVOLVE_UNLICENSED_MSG,
        routes_manifest: true,
    },
    Addon {
        name: "identity",
        // Identity is core and on by default. Bringing your own identity
        // provider (SCIM sync, OIDC/SAML login federation) is an add-on.
        default_on: true,
        disabled_msg: IDENTITY_DISABLED_MSG,
        requires_feature: None,
        unlicensed_msg: "",
        routes_manifest: false,
    },
    Addon {
        name: "trellion_intel",
        default_on: false,
        disabled_msg: INTEL_DISABLED_MSG,
        requires_feature: Some("trellion_intel"),
        unlicensed_msg: INTEL_UNLICENSED_MSG,
        routes_manifest: false,
    },
];

/// Is this add-on switched on?
///
/// ONE declaration: the `addons:` map in `noomesh.yaml`. Absent means "the
/// operator did not say", which resolves to the add-on's own polarity —
/// trellion is opt-out, the licensed ones are opt-in.
///
/// There is deliberately NO per-add-on environment variable. There used to be
/// four (`NOO_TRELLION_ENABLED`, `NOO_PRO_ENABLED`, …), restated in the
/// launcher, the onboard wizard and this table, with `default_on` declared
/// twice — and a value with two homes gets a silent winner, which is the
/// single most repeated failure in this repo. One home, one winner.
///
/// Pure so the polarity contract is testable without touching a file.
pub fn resolve(declared: Option<bool>, default_on: bool) -> bool {
    declared.unwrap_or(default_on)
}

/// Legacy shape, kept ONLY for the retired-flag guard: interpret an
/// environment value under an add-on's polarity. Nothing routes through this
/// any more — `noo stack start` uses it to say what an old `.env` flag MEANT
/// before telling the operator to move it.
pub fn flag_enabled(raw: Option<&str>, default_on: bool) -> bool {
    let v = raw.unwrap_or_default().trim().to_ascii_lowercase();
    if default_on {
        !matches!(v.as_str(), "0" | "false" | "no" | "off")
    } else {
        matches!(v.as_str(), "1" | "true" | "yes" | "on")
    }
}

/// An add-on's state: the flag AND, for licensed add-ons, the entitlement
/// (before this, the flag alone was the only gate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddonState {
    Enabled,
    /// Flag off — the operator's choice.
    Disabled,
    /// Flag on but the entitlement does not grant the feature — the
    /// licence's choice.
    Unlicensed(String),
}

/// Pure so the two-switch contract is testable without env races.
pub fn state_from(flag_on: bool, licence: Option<Result<(), String>>) -> AddonState {
    if !flag_on {
        return AddonState::Disabled;
    }
    match licence {
        None | Some(Ok(())) => AddonState::Enabled,
        Some(Err(why)) => AddonState::Unlicensed(why),
    }
}

/// The named add-on's state. Unknown names are `Disabled` — an add-on that
/// never declared itself in [`ADDONS`] does not exist.
pub fn state(name: &str) -> AddonState {
    let Some(a) = ADDONS.iter().find(|a| a.name == name) else {
        return AddonState::Disabled;
    };
    let declared = crate::config::global().addons.get(name).copied();
    let flag_on = resolve(declared, a.default_on);
    state_from(flag_on, a.requires_feature.map(crate::entitlement::licensed))
}

/// Is the named add-on usable (flag on AND licensed where required)?
pub fn enabled(name: &str) -> bool {
    state(name) == AddonState::Enabled
}

/// The operator-facing reason the add-on refused, for whichever switch is
/// missing — "turned off" and "not licensed" read differently on purpose.
pub fn refusal_msg(name: &str) -> String {
    let Some(a) = ADDONS.iter().find(|a| a.name == name) else {
        return format!("unknown add-on `{name}`");
    };
    match state(name) {
        AddonState::Enabled => String::new(),
        AddonState::Disabled => a.disabled_msg.to_string(),
        AddonState::Unlicensed(why) => format!("{} ({why})", a.unlicensed_msg),
    }
}

/// `/health` word: enabled | unhealthy | disabled | unlicensed.
pub fn health_word(name: &str) -> &'static str {
    match state(name) {
        // On, but its route manifest was missing or refused at startup: a
        // fault, not a choice (`addon_proxy::refusal` carries the reason).
        AddonState::Enabled if crate::addon_proxy::refusal(name).is_some() => "unhealthy",
        AddonState::Enabled => "enabled",
        AddonState::Disabled => "disabled",
        AddonState::Unlicensed(_) => "unlicensed",
    }
}

/// Is the trellion knowledge pack enabled on this install? Default ON —
/// today's shape. The launcher passes the same flag it uses to decide
/// whether to start the container (phase 4), so config and containers
/// cannot disagree.
pub fn trellion_enabled() -> bool {
    enabled("trellion")
}

/// Subjects owned by the trellion pack — the ML side of the
/// NOO_WORKER_SURFACES split (noomesh/workers/__init__.py is the
/// mirror; tests/test_worker_surfaces.py pins the Python half).
pub fn is_trellion_subject(subject: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "worker.rag.",
        "worker.memory.",
        "worker.recall.",
        "worker.api.snapshots.",
    ];
    PREFIXES.iter().any(|p| subject.starts_with(p))
        || subject == "worker.autonomy.check_rag"
}

/// Subjects owned by the Intelligent tier — the graph
/// engine's surface, served by the trellion-intel container
/// (NOO_WORKER_SURFACES=ml-intel; the Python mirror is
/// _ML_INTEL_MODULES in noomesh/workers/__init__.py):
/// temporal extraction plus the ML heartbeat action shell
/// (heartbeat_actions::TRELLION_ACTIONS dispatch on run_ml so they land
/// on the container that can run them; the core dispatch shell keeps
/// worker.api.heartbeat.run).
pub fn is_trellion_intel_subject(subject: &str) -> bool {
    subject.starts_with("worker.temporal.")
        || subject == "worker.api.heartbeat.run_ml"
        // The whole `worker.graph.*` family. Every one of them calls a
        // module the trellion-intel add-on carries outside trellion's open
        // tree — navigator, classifier, embedder,
        // clusterer, relation extractor, retrieval tracker — so only the
        // trellion-intel container can answer any of them.
        //
        // A prefix rather than a list: the next graph capability is intel by
        // default, which is the safe direction. A capability that later gets
        // an open baseline has to be taken OUT deliberately, and that is
        // exactly the decision that should not happen by omission.
        || subject.starts_with("worker.graph.")
        // The retrieval tracker (learned source priors, fed by
        // `worker.retrieval.feedback`) is part of the Intelligent
        // tier add-on — the same package the graph family lives in. Until 2026-09-28
        // this prefix sat in the open pack's list while its only handler
        // imported a module the noo-trellion image does not carry; every
        // publish was answered `success` and recorded nothing.
        || subject.starts_with("worker.retrieval.")
}

/// Is the Intelligent tier (trellion-intel container) usable? Default
/// OFF — it is the licensed pack, evolve's polarity — and even when the
/// flag is on it needs an entitlement granting `trellion_intel`.
pub fn trellion_intel_enabled() -> bool {
    enabled("trellion_intel")
}

/// Kept for the call sites that pre-date the generic table
/// The generic table makes every licensed add-on go through [`refusal_msg`].
pub fn intel_refusal_msg() -> String {
    refusal_msg("trellion_intel")
}

/// Is the evolve add-on enabled? Default OFF —
/// opt-in, the inverse polarity of trellion. Same switch the launcher uses
/// to decide whether the evolve overlay is composed at all, so config and
/// containers cannot disagree.
pub fn evolve_enabled() -> bool {
    enabled("evolve")
}

/// The refusal when `addons.evolve` is on but no entitlement grants `evolve`.
pub const EVOLVE_UNLICENSED_MSG: &str =
    "evolve requires a licensed entitlement granting `evolve` — none is installed on \
     this controller. Install one with `noo security entitlement install <token>` and \
     restart the stack";

/// The operator-facing explanation for the evolve refusal (proxied routes
/// in routes/evolve_proxy.rs).
pub const EVOLVE_DISABLED_MSG: &str =
    "evolve add-on disabled — this install runs without the self-tuning engines \
     (declare `addons.evolve: true` in noomesh.yaml — `noo addons enable evolve` — \
     and run `noo stack start` to enable the hofstadter loop, GA and RL policy)";

/// Marker prefix carried in the Err so callers that want a nicer message
/// than "Worker unavailable" can detect the deliberate-refusal case.
pub const DISABLED_MARKER: &str = "trellion add-on disabled";

/// Same marker contract for the Intelligent tier.
pub const INTEL_DISABLED_MARKER: &str = "trellion-intel add-on disabled";

/// The refusal when the flag is on but no valid entitlement is installed.
pub const INTEL_UNLICENSED_MSG: &str =
    "trellion-intel requires the Intelligent tier, a licensed add-on — no valid \
     entitlement is installed on this controller. Install one with `noo security \
     entitlement install <token>` and restart the stack";

/// The operator-facing explanation for the Intelligent-tier refusal.
/// Retrieval endpoints never carry this — they fall back to vector-only
/// (the P0 seams in noo-trellion); only the intel-exclusive surfaces
/// (temporal extraction, the ML heartbeat actions) refuse.
pub const INTEL_DISABLED_MSG: &str =
    "trellion-intel disabled — this install runs the open knowledge tier \
     (vector retrieval, ingest, live graph construction). Declare \
     `addons.trellion_intel: true` in noomesh.yaml and run `noo stack start` \
     to enable graph-guided retrieval, temporal extraction and the \
     self-updating graph actions";

/// The operator-facing explanation, used wherever the refusal surfaces.
pub const DISABLED_MSG: &str =
    "knowledge subsystem disabled — this install runs without the trellion \
     add-on (declare `addons.trellion: true` in noomesh.yaml and run \
     `noo stack start` to enable RAG, memory search, recall memory and the \
     knowledge graph)";

/// On by default, and turning it OFF is the unusual act —
/// the surface mints nothing until an operator issues an
/// `identity`-scoped service key, which is operator-only and must be
/// bound to an account. No key, no access; the door refuses everything
/// else before the handler is reached.
pub const IDENTITY_DISABLED_MSG: &str =
    "identity add-on disabled — this install does not run the agent identity exchange \
     (set `addons.identity: true` in noomesh.yaml to enable minting short-lived \
     per-agent tokens from a provisioning key)";

/// Is the agent identity exchange usable? Free and on
/// unless an operator turned it off.
pub fn identity_enabled() -> bool {
    enabled("identity")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn licensed_addons_need_both_switches_open_ones_only_the_flag() {
        assert_eq!(state_from(false, None), AddonState::Disabled);
        assert_eq!(state_from(false, Some(Err("x".into()))), AddonState::Disabled);
        assert_eq!(state_from(true, None), AddonState::Enabled);
        assert_eq!(state_from(true, Some(Ok(()))), AddonState::Enabled);
        assert_eq!(state_from(true, Some(Err("no entitlement installed".into()))),
                   AddonState::Unlicensed("no entitlement installed".into()));
    }

    #[test]
    fn an_unstated_addon_falls_back_to_its_own_polarity() {
        // The distinction the whole map rests on. `None` is "the operator did
        // not say", NOT "off" — collapsing them would silently disable
        // trellion on every install that never wrote an addons: section,
        // taking the entire knowledge plane with it.
        assert!(resolve(None, true), "unstated opt-out add-on stays ON");
        assert!(!resolve(None, false), "unstated opt-in add-on stays OFF");
        // An explicit answer always wins over the polarity.
        assert!(!resolve(Some(false), true), "explicit false disables an opt-out add-on");
        assert!(resolve(Some(true), false), "explicit true enables an opt-in add-on");
    }

    #[test]
    fn polarity_matches_what_an_operator_expects_to_have() {
        // trellion is the knowledge plane people assume is present; the
        // licensed ones must never arrive switched on.
        let by = |n: &str| ADDONS.iter().find(|a| a.name == n).unwrap();
        assert!(by("trellion").default_on, "trellion is opt-out");
        assert!(!by("evolve").default_on, "a licensed add-on must be opt-in");
        assert!(!by("trellion_intel").default_on, "a licensed add-on must be opt-in");
        for a in ADDONS {
            if a.requires_feature.is_some() {
                assert!(!a.default_on, "{}: licensed add-ons are never default-on", a.name);
            }
        }
    }

    #[test]
    fn the_table_declares_licences_where_the_product_says_so() {
        let by = |n: &str| ADDONS.iter().find(|a| a.name == n).unwrap();
        assert_eq!(by("trellion").requires_feature, None);
        assert_eq!(by("evolve").requires_feature, Some("evolve"));
        assert_eq!(by("trellion_intel").requires_feature, Some("trellion_intel"));
        for a in ADDONS {
            assert_eq!(a.requires_feature.is_some(), !a.unlicensed_msg.is_empty(), "{}: a licensed add-on needs its unlicensed message and vice versa", a.name);
        }
    }

    #[test]
    fn trellion_subjects_recognized() {
        for s in [
            "worker.rag.query",
            "worker.memory.search",
            "worker.recall.lifecycle",
            "worker.recall.search",
            "worker.api.snapshots.consolidate",
            "worker.autonomy.check_rag",
        ] {
            assert!(is_trellion_subject(s), "{s}");
        }
        // The Intelligent tier's subjects moved to their own predicate
        // — no subject may be double-owned.
        for s in ["worker.temporal.extract", "worker.api.heartbeat.run_ml",
                  "worker.graph.recluster", "worker.graph.navigate",
                  "worker.graph.classify_intent", "worker.graph.recall_traversals",
                  "worker.retrieval.feedback"] {
            assert!(is_trellion_intel_subject(s), "{s}");
            assert!(!is_trellion_subject(s), "{s} double-owned");
        }
        assert!(!is_trellion_intel_subject("worker.rag.query"));
    }

    /// PINNED: the two polarities. Opt-out addons
    /// (trellion) are on unless explicitly off; opt-in addons (evolve,
    /// and every future pro/licensed pack) are off unless explicitly on.
    /// Pure over the value — no process-env races.
    #[test]
    fn flag_polarity_contract() {
        // opt-out: unset/garbage/affirmative all mean ON; only the four
        // explicit negatives turn it off.
        for v in [None, Some(""), Some("1"), Some("true"), Some("banana")] {
            assert!(flag_enabled(v, true), "{v:?}");
        }
        for v in ["0", "false", "no", "off", " OFF "] {
            assert!(!flag_enabled(Some(v), true), "{v}");
        }
        // opt-in: unset/garbage/negatives all mean OFF; only the four
        // explicit affirmatives turn it on.
        for v in [None, Some(""), Some("0"), Some("banana"), Some("off")] {
            assert!(!flag_enabled(v, false), "{v:?}");
        }
        for v in ["1", "true", "yes", "on", " On "] {
            assert!(flag_enabled(Some(v), false), "{v}");
        }
    }

    #[test]
    fn addon_table_is_the_registry() {
        // The two shipped addons are rows; an undeclared name is not an
        // addon and never reads env.
        assert!(ADDONS.iter().any(|a| a.name == "trellion" && a.default_on));
        assert!(ADDONS.iter().any(|a| a.name == "evolve" && !a.default_on));
        assert!(!enabled("no-such-addon"));
    }

    #[test]
    fn core_subjects_not_gated() {
        for s in [
            "worker.tool.generic",
            "worker.api.coding.task",
            "worker.api.heartbeat.run",
        ] {
            assert!(!is_trellion_subject(s), "{s}");
        }
    }
}
