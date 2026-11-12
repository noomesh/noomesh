// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The upgrade dependency map (i613): what each thing a bundle may carry
//! needs from the node or seat that receives it, declared once.
//!
//! Before this module the floors lived next to their gates
//! (`node_leaves`, `cluster_vendor`, `provision`), each judged by the node's
//! PRE-apply version and each with its own rule for an unreadable version.
//! [`DEPS`] holds one row per gate; the `applier_knows_*` functions are thin
//! readers of it ([`meets`]), and [`decide`] adds what the readers cannot
//! say: whether the bundle being staged installs what the item needs, so
//! the item can follow in the next wave of the same run instead of a second
//! `noo upgrade`.
//!
//! Slice 1 (this file) changes no answer: every reader returns what its old
//! floor check returned, for every version string a node reports. The wave
//! loop, the seat wait and `--plan` read [`decide`] / [`decide_seat`] in
//! later slices.

use super::node_leaves::cli_version_triple;

/// `(major, minor, patch)`, as [`cli_version_triple`] reads it.
pub(crate) type Version = (u32, u32, u32);

/// One thing a bundle can carry that a receiver might not be able to take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Item {
    /// `svc-addon-*` door leaves (`node_leaves::applier_knows_addon_leaf_kinds`).
    AddonLeaves,
    /// The static `svc-*` door leaves on a Mac (`node_leaves::applier_knows_leaf_kinds`).
    MacLeaves,
    /// The harness bundle kinds (`provision::applier_knows_harness_kinds`).
    Harness,
    /// The vendor CLI kinds (`cluster_vendor::applier_knows_vendor_kinds`).
    VendorKinds,
    /// Vendor slots 2 and up (`cluster_vendor::applier_knows_vendor_slots`).
    VendorSlots,
    /// The cluster-trust keys in `agent-env` (`provision::applier_knows_cluster_trust_keys`).
    ClusterTrustKeys,
    /// The seat's display showing the controller's console build.
    SeatDisplay,
    /// The kiosk scripts, which wait for the seat's shared kiosk dir
    /// (`kiosk_seat::defer_kiosk_until_shared_dir`).
    KioskSharedDir,
}

/// Who the row applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Every node, whatever its OS.
    AnyNode,
    /// A macOS node only: on Linux the applier rides the bundle and
    /// self-updates before it validates, so the gate never applies.
    MacNode,
    /// A kiosk seat.
    Seat,
}

/// What the receiver must have before the item is safe to send.
// `HostFact`'s name is read by the tests now and by the remedy text of a
// later slice; nothing in a non-test build prints it yet.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Need {
    /// The node's applier/CLI at or above this release.
    Applier(Version),
    /// The seat's page reports the controller's console build.
    ConsoleBuildIsController,
    /// Something only root on the box can do; no bundle meets it.
    HostFact(&'static str),
}

/// What today's gate does when the node's version is empty or unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unknown {
    /// Assume the receiver can take it.
    Include,
    /// Assume it cannot; leave the item out.
    Withhold,
}

/// One row of the map.
pub(crate) struct Dep {
    pub(crate) item: Item,
    pub(crate) scope: Scope,
    pub(crate) need: Need,
    pub(crate) unknown: Unknown,
    /// Does a bundle that holds the item also install what meets the need?
    /// True for an applier floor (every bundle carries the new CLI/applier)
    /// and for the seat display (the seat bundle carries the console); false
    /// for a host fact.
    pub(crate) carried: bool,
    // Read by the tests now and by `--plan` in a later slice.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) why: &'static str,
}

/// The map: one row per item. The floors live HERE; the old constant names
/// that are still read elsewhere ([`super::node_leaves::LEAF_KINDS_MAC_FLOOR`])
/// are [`floor`] of their row.
pub(crate) const DEPS: &[Dep] = &[
    Dep {
        item: Item::AddonLeaves,
        scope: Scope::AnyNode,
        need: Need::Applier((0, 6, 18)),
        unknown: Unknown::Withhold,
        carried: true,
        why: "no applier before 0.6.18 knows the svc-addon-* kinds and it refuses the whole bundle on one (exit 76); \
              an unknown applier is withheld them because a wrong guess fails the bundle",
    },
    Dep {
        item: Item::MacLeaves,
        scope: Scope::MacNode,
        need: Need::Applier((0, 5, 63)),
        unknown: Unknown::Include,
        carried: true,
        why: "the Mac applier is its noo binary, which learned the svc-* kinds in noo-cli 0.5.63; \
              an unknown version is assumed able, as for the harness kinds",
    },
    Dep {
        item: Item::Harness,
        scope: Scope::MacNode,
        need: Need::Applier((0, 5, 40)),
        unknown: Unknown::Include,
        carried: true,
        why: "the Mac applier learned the harness kinds in noo-cli 0.5.40; an unknown version is assumed able, \
              because withholding would silently drop the harness from every node whose version was not read",
    },
    Dep {
        item: Item::VendorKinds,
        scope: Scope::MacNode,
        need: Need::Applier((0, 6, 5)),
        unknown: Unknown::Include,
        carried: true,
        why: "the Mac applier learned the vendor CLI kinds in 0.6.5",
    },
    Dep {
        item: Item::VendorSlots,
        scope: Scope::MacNode,
        need: Need::Applier((0, 6, 8)),
        unknown: Unknown::Include,
        carried: true,
        why: "the Mac applier learned vendor slots 2 and up in 0.6.8; an older one gets slot 1 only",
    },
    Dep {
        item: Item::ClusterTrustKeys,
        scope: Scope::MacNode,
        need: Need::Applier((0, 6, 10)),
        unknown: Unknown::Withhold,
        carried: true,
        why: "the cluster-trust agent-env keys first shipped in noo-cli 0.6.10 and an older Mac applier refuses \
              the bundle on them (exit 65); omitting them is harmless, so an unknown version is withheld them",
    },
    Dep {
        item: Item::SeatDisplay,
        scope: Scope::Seat,
        need: Need::ConsoleBuildIsController,
        unknown: Unknown::Include,
        carried: true,
        why: "the seat's page reports the console build only after it reloads, one heartbeat after the apply; \
              a seat that states no build is a warning, not a stop",
    },
    Dep {
        item: Item::KioskSharedDir,
        scope: Scope::Seat,
        need: Need::HostFact("kiosk-shared-dir"),
        unknown: Unknown::Withhold,
        carried: false,
        why: "the kiosk scripts install into the seat's shared kiosk dir, which only root creates \
              (kiosk seat-sync --migrate); until then they are deferred",
    },
];

/// The row for `item`. A missing row panics, at compile time for every
/// `const` that calls [`floor`].
const fn row(item: Item) -> &'static Dep {
    let mut i = 0;
    while i < DEPS.len() {
        if DEPS[i].item as u8 == item as u8 {
            return &DEPS[i];
        }
        i += 1;
    }
    panic!("an upgrade_deps::Item has no DEPS row");
}

/// The applier floor of `item`'s row. Panics for a row whose need is not an
/// applier floor (in a `const`, that is a compile error).
pub(crate) const fn floor(item: Item) -> Version {
    match row(item).need {
        Need::Applier(v) => v,
        Need::ConsoleBuildIsController | Need::HostFact(_) => panic!("this DEPS row has no applier floor"),
    }
}

/// What is known about a node when a bundle is staged for it.
pub(crate) struct NodeFacts<'a> {
    /// The node record's `app_version` (`stack-v…` on Linux, `noo-cli-v…`
    /// on a Mac, possibly empty).
    pub(crate) app_version: &'a str,
    pub(crate) is_mac: bool,
}

/// What is known about a seat after its apply.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SeatFacts<'a> {
    /// The heartbeat's `console_build`, possibly empty.
    pub(crate) console_build: &'a str,
    /// The controller's stack tag (`cluster_verify::controller_stack_tag`).
    pub(crate) controller_tag: &'a str,
    pub(crate) kiosk_shared_dir: bool,
}

/// What to do with one item for one receiver.
// The needs inside `NextWave`/`Blocked` are read by the tests now and by the
// wave loop in a later slice; the slice-1 readers only ask "include or not".
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Send it now.
    Include,
    /// Not now, but this bundle installs what it needs: send it in the next
    /// wave of the same run, once the receiver reports the new version.
    NextWave(Need),
    /// Nothing this run installs meets the need.
    Blocked(Need),
    /// The row does not apply to this receiver (a Mac item on Linux).
    NotApplicable,
}

/// Decide one node item.
///
/// - Include when the live version meets the need. An empty or unreadable
///   version follows the row's [`Unknown`]: `Include` includes, `Withhold`
///   counts as below the floor.
/// - NextWave(need) when it does not, but the row is `carried` and
///   `installs` (the CLI/applier this bundle installs) meets the floor.
/// - Blocked(need) otherwise, and always for a need that is not an applier
///   floor.
/// - NotApplicable for a Mac row on a non-Mac node, or a seat row.
pub(crate) fn decide(item: Item, facts: &NodeFacts<'_>, installs: Option<Version>) -> Decision {
    let dep = row(item);
    let applies = match dep.scope {
        Scope::AnyNode => true,
        Scope::MacNode => facts.is_mac,
        Scope::Seat => false,
    };
    if !applies {
        return Decision::NotApplicable;
    }
    let Need::Applier(min) = dep.need else {
        return Decision::Blocked(dep.need);
    };
    let live = match cli_version_triple(facts.app_version) {
        Some(v) => v >= min,
        None => dep.unknown == Unknown::Include,
    };
    if live {
        Decision::Include
    } else if dep.carried && installs.is_some_and(|v| v >= min) {
        Decision::NextWave(dep.need)
    } else {
        Decision::Blocked(dep.need)
    }
}

/// Decide one seat item. The display is met when the seat's console build
/// is the controller's tag (compared as `kiosk_seat`'s display check does);
/// an unstated build follows the row's [`Unknown`]. A display still on the
/// old build is the next wave: the seat bundle carries the console and the
/// page reloads after the apply. The shared kiosk dir is a host fact.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decide_seat(item: Item, facts: &SeatFacts<'_>) -> Decision {
    let dep = row(item);
    let met = match item {
        Item::SeatDisplay if facts.console_build.trim().is_empty() => dep.unknown == Unknown::Include,
        Item::SeatDisplay => {
            super::kiosk_seat::norm_tag(facts.console_build) == super::kiosk_seat::norm_tag(facts.controller_tag)
        }
        Item::KioskSharedDir => facts.kiosk_shared_dir,
        Item::AddonLeaves
        | Item::MacLeaves
        | Item::Harness
        | Item::VendorKinds
        | Item::VendorSlots
        | Item::ClusterTrustKeys => return Decision::NotApplicable,
    };
    if met {
        Decision::Include
    } else if dep.carried {
        Decision::NextWave(dep.need)
    } else {
        Decision::Blocked(dep.need)
    }
}

/// The slice-1 reader behind every `applier_knows_*`: may this item go in a
/// bundle for a node reporting `app_version`, judged by the live version
/// alone (no next wave yet)? Include and NotApplicable say yes.
pub(crate) fn meets(item: Item, darwin: bool, app_version: &str) -> bool {
    matches!(
        decide(item, &NodeFacts { app_version, is_mac: darwin }, None),
        Decision::Include | Decision::NotApplicable
    )
}

/// Has a node REPORTED a version at or above `item`'s applier floor? A wait,
/// not a staging guess: an empty or unreadable version is not there yet,
/// whatever the row's [`Unknown`] says (`upgrade::reached_leaf_floor`).
pub(crate) fn reached(item: Item, app_version: &str) -> bool {
    cli_version_triple(app_version).is_some_and(|v| v >= floor(item))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The strings nodes actually report (0.6.20 roll): a Linux node its
    // applier's stack tag with the full commit, a Mac its CLI tag, the
    // controller a dirty dev build, and a node that has not reported.
    const LINUX_0_6_20: &str = "stack-v0.6.20+07ce5047d5fd3b1e6c0a2f9d4e8b7a6c5d4e3f21";
    const LINUX_0_6_19: &str = "stack-v0.6.19+5b2c9e0a7d3f4e1b8c6a2d9f0e7b4c3a1d5e6f78";
    const LINUX_0_6_17: &str = "stack-v0.6.17+abc";
    const MAC_0_6_19: &str = "noo-cli-v0.6.19+5b2c9e0";
    const MAC_0_5_62: &str = "noo-cli-v0.5.62+abc";
    const CONTROLLER_DIRTY: &str = "noo-cli-v0.6.21-dirty+07ce504";
    const EMPTY: &str = "";

    const VERSIONS: [&str; 13] = [
        LINUX_0_6_20,
        LINUX_0_6_19,
        LINUX_0_6_17,
        MAC_0_6_19,
        MAC_0_5_62,
        CONTROLLER_DIRTY,
        "v0.6.21-dirty+07ce504",
        EMPTY,
        "dev",
        "noo-cli-v0.5.35+7b00c90",
        "noo-cli-v0.6.7",
        "noo-cli-v0.6.9+abc",
        "noo-cli-v0.6.10",
    ];

    /// One old gate, written out as it read before the map: its floor, its
    /// platform and its unknown-version answer.
    struct Old {
        name: &'static str,
        read: fn(bool, &str) -> bool,
        floor: Version,
        mac_only: bool,
        unknown_includes: bool,
    }

    fn old_answer(o: &Old, darwin: bool, v: &str) -> bool {
        if o.mac_only && !darwin {
            return true;
        }
        match crate::commands::node_leaves::cli_version_triple(v) {
            Some(t) => t >= o.floor,
            None => o.unknown_includes,
        }
    }

    fn olds() -> [Old; 6] {
        [
            Old {
                name: "leaf kinds",
                read: crate::commands::node_leaves::applier_knows_leaf_kinds,
                floor: (0, 5, 63),
                mac_only: true,
                unknown_includes: true,
            },
            Old {
                name: "add-on leaf kinds",
                read: |_, v| crate::commands::node_leaves::applier_knows_addon_leaf_kinds(v),
                floor: (0, 6, 18),
                mac_only: false,
                unknown_includes: false,
            },
            Old {
                name: "harness kinds",
                read: crate::commands::provision::applier_knows_harness_kinds,
                floor: (0, 5, 40),
                mac_only: true,
                unknown_includes: true,
            },
            Old {
                name: "vendor kinds",
                read: crate::commands::cluster_vendor::applier_knows_vendor_kinds,
                floor: (0, 6, 5),
                mac_only: true,
                unknown_includes: true,
            },
            Old {
                name: "vendor slots",
                read: crate::commands::cluster_vendor::applier_knows_vendor_slots,
                floor: (0, 6, 8),
                mac_only: true,
                unknown_includes: true,
            },
            Old {
                name: "cluster trust keys",
                read: crate::commands::provision::applier_knows_cluster_trust_keys,
                floor: (0, 6, 10),
                mac_only: true,
                unknown_includes: false,
            },
        ]
    }

    /// Slice 1 changes no answer: every reader, for every real version
    /// string on both platforms, says what its old floor check said.
    #[test]
    fn every_reader_answers_what_its_old_floor_check_answered() {
        for o in olds() {
            let mut answers = Vec::new();
            for v in VERSIONS {
                for darwin in [false, true] {
                    let want = old_answer(&o, darwin, v);
                    assert_eq!((o.read)(darwin, v), want, "{}: darwin={darwin} version={v:?}", o.name);
                    answers.push(want);
                }
            }
            // The table must reach both sides of every floor, or it proves nothing.
            assert!(answers.contains(&true) && answers.contains(&false), "{}: the versions never cross its floor", o.name);
        }
    }

    /// The old floors, moved: each reader's row holds the number its gate had.
    #[test]
    fn the_floors_moved_unchanged() {
        for (item, want) in [
            (Item::AddonLeaves, (0, 6, 18)),
            (Item::MacLeaves, (0, 5, 63)),
            (Item::Harness, (0, 5, 40)),
            (Item::VendorKinds, (0, 6, 5)),
            (Item::VendorSlots, (0, 6, 8)),
            (Item::ClusterTrustKeys, (0, 6, 10)),
        ] {
            assert_eq!(floor(item), want, "{item:?}");
        }
        let leaf: Version = crate::commands::node_leaves::LEAF_KINDS_MAC_FLOOR;
        assert_eq!(leaf, floor(Item::MacLeaves));
    }

    fn linux(app_version: &str) -> NodeFacts<'_> {
        NodeFacts { app_version, is_mac: false }
    }

    fn mac(app_version: &str) -> NodeFacts<'_> {
        NodeFacts { app_version, is_mac: true }
    }

    /// Include: the 0.6.19 -> 0.6.20 Linux roll. A node live on 0.6.19
    /// meets the 0.6.18 add-on leaf floor, so its leaf goes in the first
    /// bundle; so does the 0.6.20 node and a Mac on 0.6.19.
    #[test]
    fn a_live_version_at_or_above_the_floor_is_included() {
        assert_eq!(decide(Item::AddonLeaves, &linux(LINUX_0_6_19), Some((0, 6, 20))), Decision::Include);
        assert_eq!(decide(Item::AddonLeaves, &linux(LINUX_0_6_20), None), Decision::Include);
        assert_eq!(decide(Item::AddonLeaves, &mac(MAC_0_6_19), None), Decision::Include);
        assert_eq!(decide(Item::ClusterTrustKeys, &mac(CONTROLLER_DIRTY), None), Decision::Include);
    }

    /// NextWave: live 0.6.17, and the bundle installs 0.6.20, which meets
    /// the floor. The leaf follows in the same run once the node reports it.
    #[test]
    fn below_the_floor_with_a_bundle_that_installs_it_is_the_next_wave() {
        assert_eq!(
            decide(Item::AddonLeaves, &linux(LINUX_0_6_17), Some((0, 6, 20))),
            Decision::NextWave(Need::Applier((0, 6, 18)))
        );
        assert_eq!(
            decide(Item::AddonLeaves, &linux(LINUX_0_6_17), Some((0, 6, 18))),
            Decision::NextWave(Need::Applier((0, 6, 18))),
            "installing exactly the floor meets it"
        );
    }

    /// Blocked: live 0.6.17 and nothing installs the floor (no installs
    /// stated, or a bundle that installs less).
    #[test]
    fn below_the_floor_with_nothing_that_installs_it_is_blocked() {
        assert_eq!(decide(Item::AddonLeaves, &linux(LINUX_0_6_17), None), Decision::Blocked(Need::Applier((0, 6, 18))));
        assert_eq!(
            decide(Item::AddonLeaves, &linux(LINUX_0_6_17), Some((0, 6, 17))),
            Decision::Blocked(Need::Applier((0, 6, 18)))
        );
    }

    /// A Mac below the static leaf floor whose bundle installs a newer CLI
    /// gets its leaves in the next wave (what `mac_leaves_pass` does by hand).
    #[test]
    fn a_mac_below_the_leaf_floor_gets_its_leaves_in_the_next_wave() {
        assert_eq!(
            decide(Item::MacLeaves, &mac(MAC_0_5_62), Some((0, 6, 20))),
            Decision::NextWave(Need::Applier((0, 5, 63)))
        );
        assert_eq!(decide(Item::MacLeaves, &mac(MAC_0_5_62), None), Decision::Blocked(Need::Applier((0, 5, 63))));
    }

    /// NotApplicable: a Mac-only row on Linux, whatever the version; a seat
    /// row asked about a node; a node row asked about a seat.
    #[test]
    fn a_row_outside_its_scope_does_not_apply() {
        for item in [Item::MacLeaves, Item::Harness, Item::VendorKinds, Item::VendorSlots, Item::ClusterTrustKeys] {
            for v in VERSIONS {
                assert_eq!(decide(item, &linux(v), None), Decision::NotApplicable, "{item:?} on Linux {v:?}");
            }
        }
        for item in [Item::SeatDisplay, Item::KioskSharedDir] {
            assert_eq!(decide(item, &mac(MAC_0_6_19), None), Decision::NotApplicable, "{item:?} on a node");
        }
        let seat = SeatFacts { console_build: "stack-v0.6.20", controller_tag: "v0.6.20", kiosk_shared_dir: true };
        assert_eq!(decide_seat(Item::AddonLeaves, &seat), Decision::NotApplicable);
        assert_eq!(decide_seat(Item::MacLeaves, &seat), Decision::NotApplicable);
    }

    /// Unknown version, per row: the two withholding rows (add-on leaves on
    /// every OS, cluster-trust keys on a Mac) treat it as below the floor;
    /// the others include. A withheld item still follows in the next wave
    /// when the bundle installs the floor.
    #[test]
    fn an_unknown_version_follows_each_rows_rule() {
        let withholding: Vec<Item> = DEPS.iter().filter(|d| d.unknown == Unknown::Withhold).map(|d| d.item).collect();
        assert_eq!(withholding, [Item::AddonLeaves, Item::ClusterTrustKeys, Item::KioskSharedDir]);
        for dep in DEPS.iter().filter(|d| d.scope != Scope::Seat) {
            let Need::Applier(min) = dep.need else { panic!("{:?}: a node row with no applier floor", dep.item) };
            for v in [EMPTY, "dev", "07ce5047"] {
                let got = decide(dep.item, &mac(v), None);
                let next = decide(dep.item, &mac(v), Some((0, 6, 21)));
                match dep.unknown {
                    Unknown::Include => {
                        assert_eq!(got, Decision::Include, "{:?} {v:?}", dep.item);
                        assert_eq!(next, Decision::Include, "{:?} {v:?}", dep.item);
                    }
                    Unknown::Withhold => {
                        assert_eq!(got, Decision::Blocked(Need::Applier(min)), "{:?} {v:?}", dep.item);
                        assert_eq!(next, Decision::NextWave(Need::Applier(min)), "{:?} {v:?}", dep.item);
                    }
                }
                assert_eq!(meets(dep.item, true, v), dep.unknown == Unknown::Include, "{:?} {v:?}", dep.item);
            }
        }
    }

    /// The upgrade's wait is stricter than the stager: an unreadable
    /// version has not reached the floor, even on an including row.
    #[test]
    fn reached_needs_a_reported_version() {
        assert!(!reached(Item::MacLeaves, EMPTY));
        assert!(!reached(Item::MacLeaves, "dev"));
        assert!(!reached(Item::MacLeaves, MAC_0_5_62));
        assert!(reached(Item::MacLeaves, "noo-cli-v0.5.63"));
        assert!(reached(Item::MacLeaves, MAC_0_6_19));
        assert!(reached(Item::MacLeaves, CONTROLLER_DIRTY));
    }

    /// The seat display: the controller's build is Include, an older one is
    /// the next wave (the page reloads after the apply), an unstated one is
    /// today's warning, not a stop.
    #[test]
    fn the_seat_display_waits_for_the_controllers_console_build() {
        let seat = |console_build| SeatFacts { console_build, controller_tag: "v0.6.20", kiosk_shared_dir: true };
        assert_eq!(decide_seat(Item::SeatDisplay, &seat("stack-v0.6.20")), Decision::Include);
        assert_eq!(decide_seat(Item::SeatDisplay, &seat("stack-v0.6.20+07ce504")), Decision::Include);
        assert_eq!(
            decide_seat(Item::SeatDisplay, &seat("stack-v0.6.19")),
            Decision::NextWave(Need::ConsoleBuildIsController)
        );
        assert_eq!(decide_seat(Item::SeatDisplay, &seat(EMPTY)), Decision::Include);
        let dirty = SeatFacts { console_build: "stack-v0.6.21", controller_tag: "v0.6.21-dirty+abc1234", kiosk_shared_dir: true };
        assert_eq!(
            decide_seat(Item::SeatDisplay, &dirty),
            Decision::NextWave(Need::ConsoleBuildIsController),
            "compared as today's display check compares (kiosk_seat::norm_tag keeps the dirty suffix)"
        );
    }

    /// The shared kiosk dir is a host fact: no bundle creates it, so a seat
    /// without it is blocked, never the next wave.
    #[test]
    fn a_missing_kiosk_dir_is_blocked_on_a_host_fact() {
        let seat = |kiosk_shared_dir| SeatFacts { console_build: "stack-v0.6.20", controller_tag: "v0.6.20", kiosk_shared_dir };
        assert_eq!(
            decide_seat(Item::KioskSharedDir, &seat(false)),
            Decision::Blocked(Need::HostFact("kiosk-shared-dir"))
        );
        assert_eq!(decide_seat(Item::KioskSharedDir, &seat(true)), Decision::Include);
    }

    /// Every Item has exactly one row, every row says why, and only a host
    /// fact is not carried. The match makes a new Item a compile error here
    /// until it is listed.
    #[test]
    fn every_item_has_exactly_one_row() {
        const ALL: [Item; 8] = [
            Item::AddonLeaves,
            Item::MacLeaves,
            Item::Harness,
            Item::VendorKinds,
            Item::VendorSlots,
            Item::ClusterTrustKeys,
            Item::SeatDisplay,
            Item::KioskSharedDir,
        ];
        let index = |i: Item| match i {
            Item::AddonLeaves => 0,
            Item::MacLeaves => 1,
            Item::Harness => 2,
            Item::VendorKinds => 3,
            Item::VendorSlots => 4,
            Item::ClusterTrustKeys => 5,
            Item::SeatDisplay => 6,
            Item::KioskSharedDir => 7,
        };
        for item in ALL {
            assert_eq!(ALL[index(item)], item);
            assert_eq!(DEPS.iter().filter(|d| d.item == item).count(), 1, "{item:?} needs exactly one DEPS row");
        }
        assert_eq!(DEPS.len(), ALL.len());
        for dep in DEPS {
            assert!(!dep.why.trim().is_empty(), "{:?}: say why", dep.item);
            assert_eq!(dep.carried, !matches!(dep.need, Need::HostFact(_)), "{:?}: only a host fact is not carried", dep.item);
        }
    }

    /// Every `.rs` under src/commands, as (path relative to it, source).
    fn command_sources() -> Vec<(String, String)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("commands");
        let mut dirs = vec![root.clone()];
        let mut out = Vec::new();
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let name = path.strip_prefix(&root).unwrap().display().to_string();
                    out.push((name, std::fs::read_to_string(&path).unwrap()));
                }
            }
        }
        out
    }

    /// No command compares a version with a floor outside the map: a
    /// `*_FLOOR` next to a comparison, or a parsed version compared with a
    /// literal release on the same line, is a second floor check.
    #[test]
    fn no_command_compares_a_version_with_a_floor_outside_the_map() {
        let sources = command_sources();
        for must in ["node_leaves.rs", "provision.rs", "cluster_vendor.rs", "upgrade.rs", "kiosk_seat.rs"] {
            assert!(sources.iter().any(|(n, _)| n == must), "the guard did not read {must}");
        }
        let mut bad = Vec::new();
        for (name, src) in &sources {
            if name == "upgrade_deps.rs" {
                continue;
            }
            let code = crate::test_src::own_code(src);
            for (n, line) in code.lines().enumerate() {
                let compares = [">=", "<=", " < ", " > "].into_iter().any(|op| line.contains(op));
                let floor_cmp = compares && line.contains("_FLOOR");
                let literal_cmp = line.contains("cli_version_triple(") && (line.contains(">= (") || line.contains("< ("));
                if floor_cmp || literal_cmp {
                    bad.push(format!("{name}:{}: {}", n + 1, line.trim()));
                }
            }
        }
        assert!(bad.is_empty(), "compare against upgrade_deps (meets, reached, decide) instead: {bad:#?}");
    }

    /// Every `applier_knows_*` reads the map.
    #[test]
    fn every_applier_knows_reader_goes_through_the_map() {
        let mut seen = Vec::new();
        for (name, src) in command_sources() {
            let code = crate::test_src::own_code(&src);
            let mut rest = code.as_str();
            while let Some(at) = rest.find("fn applier_knows_") {
                let tail = &rest[at..];
                let marker = &tail[..tail.find('(').expect("a fn has a parameter list") + 1];
                let body = crate::test_src::fn_body(&code, marker);
                assert!(body.contains("upgrade_deps::"), "{name}: `{marker}` must read upgrade_deps, not its own floor");
                seen.push(marker.to_string());
                rest = &tail[marker.len()..];
            }
        }
        seen.sort();
        assert_eq!(
            seen,
            [
                "fn applier_knows_addon_leaf_kinds(",
                "fn applier_knows_cluster_trust_keys(",
                "fn applier_knows_harness_kinds(",
                "fn applier_knows_leaf_kinds(",
                "fn applier_knows_vendor_kinds(",
                "fn applier_knows_vendor_slots(",
            ]
        );
    }
}
