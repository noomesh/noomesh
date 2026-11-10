// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo addons setup <name> --plan [--node <node>] [--set <slot>=<id>@<rev>]...`:
//! the read-only planner for bringing a third-party add-on from nothing to a
//! reserved worker (i607a, slice 1).
//!
//! The plan is derived on every run from the controller's state; nothing is
//! kept between runs and nothing is changed by one. Each step is `done`,
//! `todo`, `decision` (the operator chooses or consents), `stopped` (the
//! operator must act, then plan again), `blocked` (an earlier step has to
//! settle first) or `unknown` (the check could not run: the gateway did not
//! answer). The nine steps, in order:
//!
//! 1. `trust`: a signing key is trusted for the add-on (`addon_trust`).
//! 2. `bundle`: its signed bundle is read through `resolve::fetch_and_check`,
//!    the path behind `noo addons upgrade --check` (signature, files, the
//!    declarations; no pin, no image pull). A registry refusal of access is
//!    step 2a, `registry-login`, and stops there.
//! 3. `enable`: declared on in noomesh.yaml and pinned to the offered version.
//!
//! Steps 4 to 9 apply only when the bundle ships `node-workloads.json`:
//!
//! 4. `sets:<slot>`: a staged model set that fits each declared slot.
//! 5. `licence:<set>`: the licence of each chosen set is accepted.
//! 6. `place`: the workload is placed on a node with those sets.
//! 7. `consent`: the node's heartbeat approvals hold the image digest.
//! 8. `delivery`: the node reports each placed set `verified`.
//! 9. `reserve`: a GPU reservation for the workload exists.
//!
//! Steps 6 to 9 ask the gateway; when it does not answer they are `unknown`,
//! never a failure of the whole plan. Built-in add-ons have their own path
//! and are refused.
//!
//! All the outside world (the registry, the staged model sets, the gateway)
//! sits behind [`World`], so the tests plan against stand-ins. The install's
//! own files (`.env`, noomesh.yaml, the pins) are read under the root given
//! to [`plan`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value};

use super::cluster_node_workloads::{approve_hint, list_path, parse_set, select_workloads, sets_summary, short_digest, SetArg};
use super::models_sets;
use crate::addon_lock::{TrustAnchor, VerifiedLock};
use crate::addons::lock_fetch::Fetched;
use crate::addons::node_workloads::{self, Accepts, NodeWorkload, Slot};
use crate::addons::resolve::{self, Refusal, Want};
use crate::addons::{self, pins, trust};
use crate::args::{ArgError, Args};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Glyph};
use crate::{Globals, Unhandled};

/// Where a step stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Done,
    Todo,
    Decision,
    Stopped,
    Blocked,
    Unknown,
}

impl State {
    fn word(self) -> &'static str {
        match self {
            State::Done => "done",
            State::Todo => "todo",
            State::Decision => "decision",
            State::Stopped => "stopped",
            State::Blocked => "blocked",
            State::Unknown => "unknown",
        }
    }
}

/// One line of the plan. `command` is what would run, or what the operator
/// has to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Step {
    pub id: String,
    pub state: State,
    pub detail: String,
    pub command: Option<String>,
}

fn step(id: impl Into<String>, state: State, detail: impl Into<String>, command: Option<String>) -> Step {
    Step { id: id.into(), state, detail: detail.into(), command }
}

/// A staged model set, as the planner needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Staged {
    pub id: String,
    pub revision: String,
    pub kind: String,
    pub runtime: Vec<String>,
    /// Signature verifies and the manifest validates.
    pub usable: bool,
    /// The set's licence needs the operator and no acceptance is recorded.
    pub licence_open: bool,
}

/// What the planner cannot read from the install's own files.
pub(crate) trait World {
    /// The signed bundle, read with no side effect.
    fn bundle(&self, addon: &str, anchor: &TrustAnchor, want: &Want) -> Result<(VerifiedLock, Fetched), Refusal>;
    /// Every staged model set.
    fn staged_sets(&self) -> Vec<Staged>;
    /// A gateway GET. `Err` = the gateway did not answer usefully.
    fn gateway(&self, path: &str) -> Result<Value, String>;
}

/// The production [`World`].
struct Live<'a> {
    g: &'a Globals,
}

impl World for Live<'_> {
    fn bundle(&self, addon: &str, anchor: &TrustAnchor, want: &Want) -> Result<(VerifiedLock, Fetched), Refusal> {
        let client = addons::third_party_client(addon, anchor)?;
        resolve::fetch_and_check(&client, anchor, want)
    }

    fn staged_sets(&self) -> Vec<Staged> {
        let dir = std::path::PathBuf::from(super::models_fetch::controller_store_dir());
        let public = crate::pki::ClusterCa::new(crate::pki::pki_dir()).signing_pub_path();
        models_sets::scan_for_plan(&dir, &public)
            .into_iter()
            .map(|(r, runtime, accepted)| Staged {
                usable: r.signature == "ok" && r.problem.is_none(),
                // `Row::license` says NOT ACCEPTED for a licence that needs the operator.
                licence_open: r.license == "NOT ACCEPTED" && !accepted,
                id: r.id,
                revision: r.revision,
                kind: r.kind,
                runtime,
            })
            .collect()
    }

    fn gateway(&self, path: &str) -> Result<Value, String> {
        crate::http::get_json_try(self.g, path, true, 15)
    }
}

// ── arguments ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Opts {
    pub addon: String,
    pub node: Option<String>,
    pub sets: Vec<SetArg>,
}

/// The options, and whether `--plan` was given.
pub(crate) fn parse(args: &[String]) -> Result<(Opts, bool), ArgError> {
    let mut a = Args::new(args);
    let planned = a.flag(&["--plan"]);
    let node = a.value(&["--node"])?.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let mut sets = Vec::new();
    for raw in a.values(&["--set"])? {
        sets.push(parse_set(&raw)?);
    }
    let addon = a.one("<name>")?;
    Ok((Opts { addon, node, sets }, planned))
}

/// Why setup does not take this name: `(code, message, hint)`.
fn refusal(addon: &str) -> Option<(&'static str, String, Option<String>)> {
    if !trust::name_ok(addon) {
        return Some((
            "bad_name",
            format!("`{addon}` is not an add-on name (lowercase letters, digits, - and _, starting with a letter)"),
            None,
        ));
    }
    if trust::is_builtin(addon) {
        return Some((
            "builtin",
            format!("{addon} ships with the stack and has its own path: setup is for add-ons you trust a signing key for"),
            Some(format!("noo addons enable {addon}")),
        ));
    }
    None
}

// ── the plan ────────────────────────────────────────────────────────────

fn blocked(out: &mut Vec<Step>, ids: &[&str], why: &str) {
    for id in ids {
        let detail = if *id == "workloads" {
            format!("model sets, licence, placement, consent, delivery and reserve follow if the bundle declares node workloads ({why})")
        } else {
            why.to_string()
        };
        out.push(step(*id, State::Blocked, detail, None));
    }
}

/// The trust anchor the operator gave `name`, from `root`'s noomesh.yaml.
fn anchor_at(root: &Path, name: &str) -> Result<Option<TrustAnchor>, String> {
    let path = root.join("noomesh.yaml");
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(trust::read(&text)?.remove(name))
}

/// Derive the plan from `root` and `w`. Reads only.
pub(crate) fn plan(w: &dyn World, root: &Path, o: &Opts) -> Vec<Step> {
    let addon = o.addon.as_str();
    let mut out: Vec<Step> = Vec::new();

    // 1. trust
    let anchor = match anchor_at(root, addon) {
        Err(e) => {
            out.push(step("trust", State::Stopped, format!("the trust list could not be read: {e}"), None));
            blocked(&mut out, &["bundle", "enable", "workloads"], "waiting on the trust step");
            return out;
        }
        Ok(Some(a)) if !a.keys.is_empty() || !a.dev.is_empty() => a,
        Ok(_) => {
            out.push(step(
                "trust",
                State::Decision,
                "no key is trusted for this add-on: get its public key and registry root from the publisher (never from the registry itself), then decide whether to trust it",
                Some(format!("noo addons trust-key {addon} <pubkey> --registry <root>")),
            ));
            blocked(&mut out, &["bundle", "enable", "workloads"], "nothing can be verified before a key is trusted");
            return out;
        }
    };
    out.push(step(
        "trust",
        State::Done,
        format!("{} key(s) trusted for {addon}, registry {}", anchor.keys.len() + anchor.dev.len(), anchor.registry),
        None,
    ));

    // 2. bundle
    let Some(tag) = addons::current_tag(root) else {
        out.push(step(
            "bundle",
            State::Stopped,
            "this install pins no stack tag (NOO_IMAGE_TAG), so there is no stack to read the add-on's bundle for",
            Some("noo upgrade --stack".to_string()),
        ));
        blocked(&mut out, &["enable", "workloads"], "the bundle cannot be read");
        return out;
    };
    let pinned = match pins::read(root) {
        Ok(p) => p,
        Err(e) => {
            out.push(step("bundle", State::Stopped, format!("the pins could not be read: {e}"), Some("noo addons verify".to_string())));
            blocked(&mut out, &["enable", "workloads"], "the bundle cannot be read");
            return out;
        }
    };
    let pin = pinned.get(addon);
    let stack_lock = resolve::installed_stack_lock(root, &tag);
    let want = Want {
        addon,
        stack_tag: &tag,
        stack_lock: stack_lock.as_deref(),
        pinned: pin.map(|p| p.version.as_str()),
        pin,
        allow_downgrade: false,
    };
    let (v, f) = match w.bundle(addon, &anchor, &want) {
        Ok(b) => b,
        Err(r) if r.is_auth() => {
            out.push(step("bundle", State::Blocked, "the registry refused access, so the bundle cannot be read yet", None));
            out.push(step(
                "registry-login",
                State::Stopped,
                format!(
                    "{} refused access: register a read-only pull token for {addon}, read from a file and never typed on the command line, then plan again",
                    anchor.registry
                ),
                Some(format!("noo addons registry-login {addon} --registry {} --from-file <path>", anchor.registry)),
            ));
            blocked(&mut out, &["enable", "workloads"], "waiting on the registry login");
            return out;
        }
        Err(r) => {
            out.push(step("bundle", State::Stopped, r.why(addon), Some(super::addon_enable::pin_fix(addon, &r))));
            blocked(&mut out, &["enable", "workloads"], "the bundle was refused");
            return out;
        }
    };
    let parsed: Result<Vec<NodeWorkload>, String> = match f.files.get("node-workloads.json") {
        None => Ok(Vec::new()),
        Some(bytes) => node_workloads::parse_node_workloads(addon, bytes, &v.lock.images, None).map_err(|e| e.to_string()),
    };
    let wls = match parsed {
        Ok(w) => w,
        Err(e) => {
            out.push(step(
                "bundle",
                State::Stopped,
                format!("node-workloads.json is refused: {e}; the publisher must fix and re-sign it"),
                Some(format!("noo addons upgrade {addon} --check")),
            ));
            blocked(&mut out, &["enable", "workloads"], "the bundle was refused");
            return out;
        }
    };
    out.push(step(
        "bundle",
        State::Done,
        format!(
            "version {}, signed by key #{}, {} file(s), {} image(s), {} node workload(s)",
            v.lock.version,
            v.key_index,
            v.lock.files.len(),
            v.lock.images.len(),
            wls.len()
        ),
        None,
    ));

    // 3. enable
    out.push(enable_step(root, addon, &tag, &anchor, &v.lock.version));
    if wls.is_empty() {
        return out;
    }

    // 4 to 9, per declared workload
    let staged = w.staged_sets();
    let multi = wls.len() > 1;
    let mut declared_slots = BTreeSet::new();
    for wl in &wls {
        for s in &wl.models {
            declared_slots.insert(s.slot.clone());
        }
        plan_workload(w, o, &v.lock.images, wl, multi, &staged, &mut out);
    }
    for s in &o.sets {
        if !declared_slots.contains(&s.slot) {
            out.push(step(
                format!("sets:{}", s.slot),
                State::Stopped,
                format!("--set names slot {}, which the bundle does not declare", s.slot),
                None,
            ));
        }
    }
    out
}

fn enable_step(root: &Path, addon: &str, tag: &str, anchor: &TrustAnchor, offered: &str) -> Step {
    let on = match super::addons::declared_map_at(&root.join("noomesh.yaml")) {
        Ok(m) => m.get(addon) == Some(&true),
        Err(e) => return step("enable", State::Stopped, format!("noomesh.yaml could not be read: {e}"), None),
    };
    match (on, resolve::offline_check_files(root, addon, tag, anchor)) {
        (true, Ok((pin, _))) if pin.version == offered => {
            step("enable", State::Done, format!("declared on and pinned at {offered} for stack {tag}"), None)
        }
        (true, Ok((pin, _))) => step(
            "enable",
            State::Todo,
            format!("pinned at {}, and the signed bundle offers {offered}", pin.version),
            Some(format!("noo addons upgrade {addon}")),
        ),
        (false, Ok(_)) => step(
            "enable",
            State::Todo,
            "pinned, but not declared on in noomesh.yaml",
            Some(format!("noo addons enable {addon}")),
        ),
        (true, Err(e)) => step("enable", State::Todo, format!("declared on, but not pinned: {e}"), Some(format!("noo addons enable {addon}"))),
        (false, Err(_)) => step(
            "enable",
            State::Todo,
            format!("not declared on and not pinned; enable pins {offered} and mints the service key"),
            Some(format!("noo addons enable {addon}")),
        ),
    }
}

fn fits(acc: &Option<Accepts>, s: &Staged) -> bool {
    s.usable
        && match acc {
            None => true,
            Some(a) => s.kind == a.kind && a.runtime.as_ref().is_none_or(|r| s.runtime.iter().any(|x| x == r)),
        }
}

/// Step 4 for one slot, and the `(id, revision)` pairs it settles on.
fn slot_step(o: &Opts, slot: &Slot, staged: &[Staged], sid: String) -> (Step, Vec<(String, String)>) {
    let addon = o.addon.as_str();
    let candidates: Vec<&Staged> = staged.iter().filter(|s| fits(&slot.accepts, s)).collect();
    let given: Vec<&SetArg> = o.sets.iter().filter(|s| s.slot == slot.slot).collect();
    if !given.is_empty() {
        let mut refs = Vec::new();
        for g in &given {
            if candidates.iter().any(|c| c.id == g.id && c.revision == g.revision) {
                refs.push((g.id.clone(), g.revision.clone()));
            } else {
                let why = format!("--set {}={}@{} is not a staged, signed set that fits slot {}", g.slot, g.id, g.revision, slot.slot);
                return (step(sid, State::Stopped, why, None), Vec::new());
            }
        }
        let names: Vec<String> = refs.iter().map(|(i, r)| format!("{i}@{r}")).collect();
        return (step(sid, State::Done, format!("slot {}: {} (chosen with --set)", slot.slot, names.join(", ")), None), refs);
    }
    let kind = slot.accepts.as_ref().map(|a| a.kind.clone()).unwrap_or_else(|| "<kind>".to_string());
    let runtime = slot.accepts.as_ref().and_then(|a| a.runtime.clone()).unwrap_or_else(|| "<r>".to_string());
    match candidates.as_slice() {
        [] if slot.optional => (
            step(sid, State::Done, format!("slot {}: optional, and no {kind} set is staged: skipped", slot.slot), None),
            Vec::new(),
        ),
        [] => (
            step(
                sid,
                State::Stopped,
                format!("slot {} needs a signed set of kind {kind} for runtime {runtime}, and none is staged: stage one, then plan again", slot.slot),
                Some(format!("noo models stage <hf:repo@sha> --kind {kind} --id <id> --modality <m> --runtime {runtime} --needs <file.json>")),
            ),
            Vec::new(),
        ),
        [one] => (
            step(sid, State::Done, format!("slot {}: {}@{} is the only staged set that fits", slot.slot, one.id, one.revision), None),
            vec![(one.id.clone(), one.revision.clone())],
        ),
        many => {
            let names: Vec<String> = many.iter().map(|c| format!("{}@{}", c.id, c.revision)).collect();
            (
                step(
                    sid,
                    State::Decision,
                    format!("slot {}: {} staged sets fit ({}); choose one", slot.slot, many.len(), names.join(", ")),
                    Some(format!("noo addons setup {addon} --plan --set {}=<id>@<rev>", slot.slot)),
                ),
                Vec::new(),
            )
        }
    }
}

fn chosen_summary(chosen: &BTreeMap<String, Vec<(String, String)>>) -> String {
    let parts: Vec<String> = chosen
        .iter()
        .map(|(slot, refs)| {
            let r: Vec<String> = refs.iter().map(|(i, v)| format!("{i}@{v}")).collect();
            format!("{slot}={}", r.join(","))
        })
        .collect();
    if parts.is_empty() {
        "no sets".to_string()
    } else {
        parts.join(" ")
    }
}

fn place_command(node: &str, addon: &str, workload: &str, chosen: &BTreeMap<String, Vec<(String, String)>>) -> String {
    let mut cmd = format!("noo cluster workloads place {node} {addon}/{workload}");
    for (slot, refs) in chosen {
        for (sid, rev) in refs {
            cmd.push_str(&format!(" --set {slot}={sid}@{rev}"));
        }
    }
    cmd
}

/// A placement's `sets` object as slot to `(id, revision)` pairs.
fn sets_of(sets: &Value) -> BTreeMap<String, BTreeSet<(String, String)>> {
    let mut out = BTreeMap::new();
    if let Some(map) = sets.as_object() {
        for (slot, items) in map {
            let pairs: BTreeSet<(String, String)> = items
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|i| (i["id"].as_str().unwrap_or("").to_string(), i["revision"].as_str().unwrap_or("").to_string()))
                        .collect()
                })
                .unwrap_or_default();
            if !pairs.is_empty() {
                out.insert(slot.clone(), pairs);
            }
        }
    }
    out
}

fn wanted_sets(chosen: &BTreeMap<String, Vec<(String, String)>>) -> BTreeMap<String, BTreeSet<(String, String)>> {
    chosen.iter().map(|(slot, refs)| (slot.clone(), refs.iter().cloned().collect())).collect()
}

/// Steps 4 to 9 for one workload.
fn plan_workload(
    w: &dyn World,
    o: &Opts,
    images: &BTreeMap<String, String>,
    wl: &NodeWorkload,
    multi: bool,
    staged: &[Staged],
    out: &mut Vec<Step>,
) {
    let id = |base: &str| if multi { format!("{base}@{}", wl.name) } else { base.to_string() };
    let mut chosen: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut sets_ok = true;
    for slot in &wl.models {
        let (s, refs) = slot_step(o, slot, staged, id(&format!("sets:{}", slot.slot)));
        sets_ok &= s.state == State::Done;
        if !refs.is_empty() {
            chosen.insert(slot.slot.clone(), refs);
        }
        out.push(s);
    }
    let mut seen = BTreeSet::new();
    for refs in chosen.values() {
        for (sid, rev) in refs {
            if !seen.insert(sid.clone()) {
                continue;
            }
            let open = staged.iter().any(|s| &s.id == sid && &s.revision == rev && s.licence_open);
            out.push(if open {
                step(
                    id(&format!("licence:{sid}")),
                    State::Decision,
                    format!("{sid}'s licence needs your acceptance; read the terms upstream first"),
                    Some(format!("noo models accept {sid}")),
                )
            } else {
                step(id(&format!("licence:{sid}")), State::Done, format!("{sid}'s licence is accepted or needs none"), None)
            });
        }
    }
    if !sets_ok {
        for base in ["place", "consent", "delivery", "reserve"] {
            out.push(step(id(base), State::Blocked, "the model sets above must be settled first", None));
        }
        return;
    }
    gateway_steps(w, o, images, wl, &id, &chosen, out);
}

/// Steps 6 to 9: what the gateway says.
fn gateway_steps(
    w: &dyn World,
    o: &Opts,
    images: &BTreeMap<String, String>,
    wl: &NodeWorkload,
    id: &dyn Fn(&str) -> String,
    chosen: &BTreeMap<String, Vec<(String, String)>>,
    out: &mut Vec<Step>,
) {
    let addon = o.addon.as_str();
    let rest = ["place", "consent", "delivery", "reserve"];
    let unknown = |out: &mut Vec<Step>, from: usize, why: &str| {
        for base in &rest[from..] {
            out.push(step(id(base), State::Unknown, why.to_string(), None));
        }
    };
    let nodes = match w.gateway("/api/cluster/nodes") {
        Err(e) => {
            unknown(out, 0, &format!("gateway unreachable: {e}"));
            return;
        }
        Ok(b) => match b["nodes"].as_array() {
            Some(n) => n.clone(),
            None => {
                unknown(out, 0, "the gateway's node list has no `nodes` array");
                return;
            }
        },
    };

    // Which node: --node, else wherever the workload is already placed.
    let node_id: String = match &o.node {
        Some(n) if nodes.iter().any(|x| x["id"].as_str() == Some(n.as_str())) => n.clone(),
        Some(n) => {
            out.push(step(id("place"), State::Stopped, format!("{n} is not a node of this cluster"), Some("noo cluster status".to_string())));
            for base in &rest[1..] {
                out.push(step(id(base), State::Blocked, "choose a node that exists first", None));
            }
            return;
        }
        None => {
            let mut hosts: Vec<String> = Vec::new();
            for n in &nodes {
                let Some(nid) = n["id"].as_str() else { continue };
                match w.gateway(&list_path(nid)) {
                    Ok(b) => {
                        if !select_workloads(&b, Some((addon, wl.name.as_str()))).is_empty() {
                            hosts.push(nid.to_string());
                        }
                    }
                    Err(e) => {
                        unknown(out, 0, &format!("gateway unreachable: {e}"));
                        return;
                    }
                }
            }
            if hosts.len() == 1 {
                hosts.remove(0)
            } else {
                let ids: Vec<&str> = nodes.iter().filter_map(|n| n["id"].as_str()).collect();
                let detail = if hosts.is_empty() {
                    format!("not placed anywhere yet; choose a node ({})", ids.join(", "))
                } else {
                    format!("placed on {}; name the node to plan for", hosts.join(", "))
                };
                out.push(step(id("place"), State::Decision, detail, Some(format!("noo addons setup {addon} --plan --node <node>"))));
                for base in &rest[1..] {
                    out.push(step(id(base), State::Blocked, "choose a node first", None));
                }
                return;
            }
        }
    };

    // 6. place
    let place_cmd = place_command(&node_id, addon, &wl.name, chosen);
    let body = match w.gateway(&list_path(&node_id)) {
        Ok(b) => b,
        Err(e) => {
            unknown(out, 0, &format!("gateway unreachable: {e}"));
            return;
        }
    };
    let entry = select_workloads(&body, Some((addon, wl.name.as_str()))).into_iter().next();
    let placed = match &entry {
        Some(e) if sets_of(&e["sets"]) == wanted_sets(chosen) => step(
            id("place"),
            State::Done,
            format!("placed on {node_id} ({})", e["state"].as_str().unwrap_or("state not reported")),
            None,
        ),
        Some(e) => step(
            id("place"),
            State::Todo,
            format!("placed on {node_id} with other sets ({}); the plan wants {}", sets_summary(&e["sets"]), chosen_summary(chosen)),
            Some(place_cmd),
        ),
        None => step(
            id("place"),
            State::Todo,
            format!("not placed on {node_id}; the gateway refuses until the node has consented (the next step)"),
            Some(place_cmd),
        ),
    };
    let is_placed = placed.state == State::Done;
    out.push(placed);

    // 7. consent
    let node = nodes.iter().find(|n| n["id"].as_str() == Some(node_id.as_str()));
    let digest = images.get(&wl.image).and_then(|r| r.rsplit_once('@')).map(|(_, d)| d.to_string());
    out.push(consent_step(id("consent"), addon, &node_id, node, digest));

    // 8. delivery
    out.push(delivery_step(id("delivery"), &node_id, node, chosen, is_placed));

    // 9. reserve
    out.push(if wl.accel.gpu <= 0 {
        step(id("reserve"), State::Done, "this workload needs no GPU: nothing to reserve", None)
    } else if !is_placed {
        step(id("reserve"), State::Blocked, "place the workload first", None)
    } else {
        reserve_step(id("reserve"), w, addon, &wl.name, &node_id)
    });
}

fn consent_step(sid: String, addon: &str, node_id: &str, node: Option<&Value>, digest: Option<String>) -> Step {
    let Some(node) = node else {
        return step(sid, State::Unknown, format!("{node_id} is not in the gateway's node list"), None);
    };
    let Some(digest) = digest else {
        return step(sid, State::Stopped, format!("{addon}'s lock names no image digest for this workload"), None);
    };
    match node["addon_workloads_policy"].as_str() {
        Some("auto") => step(sid, State::Done, format!("{node_id} runs any add-on workload the controller places (policy auto)"), None),
        Some("approve") => match node["addon_workloads_approvals"].as_array() {
            None => step(
                sid,
                State::Unknown,
                format!("{node_id} does not report its approvals"),
                approve_hint("consent_unapproved", node_id, addon, &digest),
            ),
            Some(list) => {
                let hit = list
                    .iter()
                    .find(|a| a["addon"].as_str() == Some(addon) && a["digest"].as_str() == Some(digest.as_str()));
                match hit {
                    Some(a) => {
                        let by = if a["source"].as_str() == Some("controller") { "the controller" } else { "the node's owner" };
                        step(sid, State::Done, format!("{addon} at {} is approved on {node_id} by {by}", short_digest(&digest)), None)
                    }
                    None => step(
                        sid,
                        State::Stopped,
                        format!("{addon} at {} is not approved on {node_id}: its owner consents on the node itself", short_digest(&digest)),
                        approve_hint("consent_unapproved", node_id, addon, &digest),
                    ),
                }
            }
        },
        Some("none") => step(
            sid,
            State::Stopped,
            format!("{node_id}'s owner has switched add-on node workloads off"),
            approve_hint("consent_none", node_id, addon, "this node's addon_workloads_policy is none"),
        ),
        Some(other) => step(sid, State::Unknown, format!("{node_id} reports an unknown consent policy `{other}`"), None),
        None => step(
            sid,
            State::Unknown,
            format!("{node_id} does not report its consent policy"),
            approve_hint("consent_none", node_id, addon, "the node does not report its addon_workloads_policy"),
        ),
    }
}

fn delivery_step(sid: String, node_id: &str, node: Option<&Value>, chosen: &BTreeMap<String, Vec<(String, String)>>, placed: bool) -> Step {
    if !placed {
        return step(sid, State::Blocked, "place the workload first", None);
    }
    let Some(node) = node else {
        return step(sid, State::Unknown, format!("{node_id} is not in the gateway's node list"), None);
    };
    let Some(rows) = node["model_sets"].as_array() else {
        return step(sid, State::Unknown, format!("{node_id} does not report its model sets"), None);
    };
    let mut lines = Vec::new();
    let mut total = 0;
    for (sid_set, rev) in chosen.values().flatten() {
        total += 1;
        let row = rows.iter().find(|r| r["id"].as_str() == Some(sid_set.as_str()) && r["revision"].as_str() == Some(rev.as_str()));
        match row {
            None => lines.push(format!("{sid_set}@{rev}: not on the node yet")),
            Some(r) => match r["state"].as_str() {
                Some("verified") => {}
                Some(state) => match r["reason"].as_str() {
                    Some(reason) => lines.push(format!("{sid_set}@{rev}: {state} ({reason})")),
                    None => lines.push(format!("{sid_set}@{rev}: {state}")),
                },
                None => lines.push(format!("{sid_set}@{rev}: no state reported")),
            },
        }
    }
    if lines.is_empty() {
        step(sid, State::Done, format!("{total} set(s) verified on {node_id}"), None)
    } else {
        step(sid, State::Todo, format!("on {node_id}: {}; plan again when they are verified", lines.join("; ")), None)
    }
}

fn reserve_step(sid: String, w: &dyn World, addon: &str, workload: &str, node_id: &str) -> Step {
    let full = format!("{addon}/{workload}");
    match w.gateway("/api/cluster/reservations") {
        Err(e) => step(sid, State::Unknown, format!("gateway unreachable: {e}"), None),
        Ok(b) => match b["reservations"].as_array() {
            None => step(sid, State::Unknown, "the gateway's reservation list has no `reservations` array", None),
            Some(list) => match list.iter().find(|r| r["workload"].as_str() == Some(full.as_str())) {
                Some(r) => step(
                    sid,
                    State::Done,
                    format!("reserved on {} ({})", r["node"].as_str().unwrap_or("?"), r["state"].as_str().unwrap_or("state not reported")),
                    None,
                ),
                None => step(
                    sid,
                    State::Todo,
                    format!("no reservation for {full}"),
                    Some(format!("noo cluster reserve {full} --node {node_id}")),
                ),
            },
        },
    }
}

// ── output ──────────────────────────────────────────────────────────────

fn label(id: &str) -> String {
    let (base, wl) = match id.split_once('@') {
        Some((b, w)) => (b, Some(w)),
        None => (id, None),
    };
    let text = match base {
        "trust" => "Trust the publisher key".to_string(),
        "bundle" => "Read the signed bundle".to_string(),
        "registry-login" => "Log in to the registry".to_string(),
        "enable" => "Enable the add-on".to_string(),
        "workloads" => "Node workloads".to_string(),
        "place" => "Place the workload".to_string(),
        "consent" => "Node consent".to_string(),
        "delivery" => "Model sets delivered".to_string(),
        "reserve" => "Reserve the GPU".to_string(),
        b if b.starts_with("sets:") => format!("Model set for {}", &b["sets:".len()..]),
        b if b.starts_with("licence:") => format!("Licence of {}", &b["licence:".len()..]),
        other => other.to_string(),
    };
    match wl {
        Some(w) => format!("{text} ({w})"),
        None => text,
    }
}

fn glyph_of(s: State) -> Glyph {
    match s {
        State::Done => Glyph::Ok,
        State::Todo => Glyph::Step,
        State::Decision | State::Unknown => Glyph::Warn,
        State::Stopped => Glyph::Err,
        State::Blocked => Glyph::Bullet,
    }
}

pub(crate) fn plan_json(addon: &str, steps: &[Step]) -> Value {
    let rows: Vec<Value> = steps
        .iter()
        .map(|s| json!({"step": s.id, "state": s.state.word(), "detail": s.detail, "command": s.command}))
        .collect();
    json!({"addon": addon, "steps": rows})
}

fn render(addon: &str, steps: &[Step]) {
    println!("{}", ui::header("add-on setup", Some(addon)));
    println!("{}", ui::section("plan"));
    let width = steps.iter().map(|s| label(&s.id).chars().count()).max().unwrap_or(0);
    for s in steps {
        let l = label(&s.id);
        let pad = " ".repeat(width.saturating_sub(l.chars().count()));
        println!("  {} {l}{pad}  {}", ui::glyph(glyph_of(s.state)), ui::muted(s.state.word()));
        if !s.detail.is_empty() {
            println!("{}", ui::note(&s.detail));
        }
    }
    let next: Vec<(String, &str)> = steps
        .iter()
        .filter_map(|s| {
            let why = match s.state {
                State::Todo => "to do",
                State::Decision => "your decision",
                State::Stopped => "run this, then plan again",
                _ => return None,
            };
            s.command.clone().map(|c| (c, why))
        })
        .collect();
    if steps.iter().all(|s| s.state == State::Done) {
        ui::close_done(&format!("{addon} is set up: every step is done"));
        return;
    }
    println!();
    println!("{}", ui::muted("plan only: nothing was changed"));
    let refs: Vec<(&str, &str)> = next.iter().map(|(c, w)| (c.as_str(), *w)).collect();
    ui::guide(&refs);
}

/// `noo addons setup <name> --plan [--node <node>] [--set <slot>=<id>@<rev>]...`
pub fn addons_setup(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (o, planned) = parse(args)?;
    if let Some((code, msg, hint)) = refusal(&o.addon) {
        fail(g.json, ExitCode::Usage, code, &msg, hint.as_deref());
    }
    if !planned {
        let hint = format!("noo addons setup {} --plan", o.addon);
        fail(g.json, ExitCode::Usage, "plan_only", "setup does not run the steps yet: they arrive in the next release", Some(&hint));
    }
    let root = crate::envfile::repo_root();
    let steps = plan(&Live { g }, &root, &o);
    if g.json {
        println!("{}", plan_json(&o.addon, &steps));
    } else {
        render(&o.addon, &steps);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addon_lock::{self, AddonLock};
    use crate::addons::resolve::tests as rt;
    use std::cell::RefCell;
    use std::path::PathBuf;

    const NW: &str = include_str!("../../../tests/fixtures/addons/rhaddon/node-workloads.json");
    const RT: &str = include_str!("../../../tests/fixtures/addons/rhaddon/routes.json");
    const NODE: &str = "node-a";

    fn image_digest() -> String {
        rt::digest('2')
    }

    fn lock_for(version: &str) -> AddonLock {
        let mut l = rt::lock(version, &["v0.6.0"], None);
        l.images.insert("addon-worker".into(), format!("{}/worker@{}", rt::ROOT, image_digest()));
        l
    }

    fn base_want<'a>() -> Want<'a> {
        Want { addon: "rhaddon", stack_tag: "v0.6.0", stack_lock: None, pinned: None, pin: None, allow_downgrade: false }
    }

    /// A signed `rhaddon` bundle with node workloads, run through the real checks.
    fn good_bundle(version: &str) -> Result<(VerifiedLock, Fetched), Refusal> {
        let f = rt::signed_rh_bundle(&lock_for(version), NW.as_bytes(), RT.as_bytes());
        let v = resolve::check(&f, &rt::anchor(), &base_want())?;
        Ok((v, f))
    }

    /// A signed `rhaddon` bundle with an overlay and nothing else.
    fn plain_bundle() -> Result<(VerifiedLock, Fetched), Refusal> {
        let mut l = lock_for("1.0.0");
        l.addon = "rhaddon".into();
        l.format = addon_lock::FORMAT_V2.into();
        let files = BTreeMap::from([(addon_lock::OVERLAY_FILE.to_string(), rt::OVERLAY.as_bytes().to_vec())]);
        l.files = files.iter().map(|(n, b)| (n.clone(), addon_lock::sha256_ref(b))).collect();
        let (bytes, sig) = addon_lock::sign(&l, &rt::seed()).unwrap();
        let f = Fetched { lock: bytes, sig, files };
        let v = resolve::check(&f, &rt::anchor(), &base_want())?;
        Ok((v, f))
    }

    fn auth_refusal() -> Refusal {
        use crate::release_fetch::{FetchClass, FetchError};
        Refusal::Fetch {
            reference: format!("{}:stack-v0.6.0", rt::ROOT),
            stack_tag: "v0.6.0".into(),
            err: Box::new(FetchError::new(FetchClass::Auth, "denied")),
            via: None,
        }
    }

    struct Fake {
        bundle: Box<dyn Fn() -> Result<(VerifiedLock, Fetched), Refusal>>,
        sets: Vec<Staged>,
        gw: BTreeMap<String, Result<Value, String>>,
        asked: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new() -> Fake {
            Fake { bundle: Box::new(|| good_bundle("1.0.0")), sets: Vec::new(), gw: BTreeMap::new(), asked: RefCell::new(Vec::new()) }
        }
        fn bundle(mut self, f: impl Fn() -> Result<(VerifiedLock, Fetched), Refusal> + 'static) -> Fake {
            self.bundle = Box::new(f);
            self
        }
        fn sets(mut self, s: Vec<Staged>) -> Fake {
            self.sets = s;
            self
        }
        fn gw(mut self, path: &str, body: Value) -> Fake {
            self.gw.insert(path.to_string(), Ok(body));
            self
        }
    }

    impl World for Fake {
        fn bundle(&self, _addon: &str, _anchor: &TrustAnchor, _want: &Want) -> Result<(VerifiedLock, Fetched), Refusal> {
            (self.bundle)()
        }
        fn staged_sets(&self) -> Vec<Staged> {
            self.sets.clone()
        }
        fn gateway(&self, path: &str) -> Result<Value, String> {
            self.asked.borrow_mut().push(path.to_string());
            self.gw.get(path).cloned().unwrap_or_else(|| Err(format!("connection refused ({path})")))
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-addon-setup-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// An install root: `.env` with a stack tag, and a noomesh.yaml that
    /// trusts rhaddon's key and/or declares it on.
    fn install(name: &str, trusted: bool, declared_on: bool) -> PathBuf {
        let d = scratch(name);
        std::fs::write(d.join(".env"), "NOO_IMAGE_TAG=v0.6.0\n").unwrap();
        let mut yaml = String::new();
        if trusted {
            yaml.push_str(&format!(
                "addon_trust:\n  rhaddon:\n    registry: {}\n    keys:\n      - \"{}\"\n",
                rt::ROOT,
                rt::anchor().keys[0]
            ));
        }
        if declared_on {
            yaml.push_str("addons:\n  rhaddon: true\n");
        }
        if !yaml.is_empty() {
            std::fs::write(d.join("noomesh.yaml"), yaml).unwrap();
        }
        d
    }

    /// Pin the good bundle at `version`, as `enable` would have.
    fn pin(root: &Path, version: &str) {
        let (v, f) = good_bundle(version).unwrap();
        resolve::record(root, "rhaddon", &v, &f, "v0.6.0", None).unwrap();
    }

    fn opts() -> Opts {
        Opts { addon: "rhaddon".into(), node: None, sets: Vec::new() }
    }

    fn st<'a>(steps: &'a [Step], id: &str) -> &'a Step {
        steps.iter().find(|s| s.id == id).unwrap_or_else(|| panic!("no step {id} in {steps:?}"))
    }

    fn ids(steps: &[Step]) -> Vec<&str> {
        steps.iter().map(|s| s.id.as_str()).collect()
    }

    fn staged(id: &str, rev: &str, kind: &str, runtime: &str) -> Staged {
        Staged { id: id.into(), revision: rev.into(), kind: kind.into(), runtime: vec![runtime.into()], usable: true, licence_open: false }
    }

    fn voice(id: &str) -> Staged {
        staged(id, "r1", "voice", "rh-s2s")
    }

    // ── the install's gateway view ──

    fn nodes_body(policy: Option<&str>, approvals: Option<Value>, model_sets: Option<Value>) -> Value {
        let mut n = json!({"id": NODE, "os": "linux"});
        if let Some(p) = policy {
            n["addon_workloads_policy"] = json!(p);
        }
        if let Some(a) = approvals {
            n["addon_workloads_approvals"] = a;
        }
        if let Some(m) = model_sets {
            n["model_sets"] = m;
        }
        json!({"nodes": [n]})
    }

    fn approved() -> Value {
        json!([{"addon": "rhaddon", "digest": image_digest()}])
    }

    fn verified() -> Value {
        json!([{"id": "rh-voice", "revision": "r1", "state": "verified"}])
    }

    fn placement(sets: Value) -> Value {
        json!({"node_id": NODE, "node_workloads": [
            {"addon": "rhaddon", "workload": "worker", "profile": null, "sets": sets, "state": "provisioned", "reservation": null}
        ]})
    }

    fn placed_main() -> Value {
        placement(json!({"main": [{"id": "rh-voice", "revision": "r1"}]}))
    }

    fn reservations(list: Value) -> Value {
        json!({"reservations": list})
    }

    fn held() -> Value {
        reservations(json!([{"id": "res-1", "workload": "rhaddon/worker", "holder": "me", "node": NODE, "state": "held"}]))
    }

    const NODES: &str = "/api/cluster/nodes";
    const PLACED: &str = "/api/cluster/nodes/node-a/node-workloads";
    const RESERVATIONS: &str = "/api/cluster/reservations";

    /// Everything done: trusted, enabled and pinned, one set, placed,
    /// consented, verified, reserved.
    fn happy(name: &str) -> (Fake, PathBuf) {
        let root = install(name, true, true);
        pin(&root, "1.0.0");
        let fake = Fake::new()
            .sets(vec![voice("rh-voice")])
            .gw(NODES, nodes_body(Some("approve"), Some(approved()), Some(verified())))
            .gw(PLACED, placed_main())
            .gw(RESERVATIONS, held());
        (fake, root)
    }

    // ── arguments and refusals ──

    #[test]
    fn the_arguments_are_a_name_a_node_and_repeatable_sets() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (o, planned) = parse(&a(&["rhaddon", "--plan", "--node", "node-a", "--set", "main=rh-voice@r1", "--set", "voices=pack@r2"])).unwrap();
        assert!(planned);
        assert_eq!(o.addon, "rhaddon");
        assert_eq!(o.node.as_deref(), Some("node-a"));
        assert_eq!(o.sets.len(), 2);
        assert_eq!((o.sets[1].slot.as_str(), o.sets[1].id.as_str(), o.sets[1].revision.as_str()), ("voices", "pack", "r2"));
        assert!(!parse(&a(&["rhaddon"])).unwrap().1, "--plan is reported absent");
        assert!(parse(&a(&["--plan"])).is_err(), "a name is required");
        assert!(parse(&a(&["rhaddon", "--plan", "--bogus"])).is_err());
        assert!(parse(&a(&["rhaddon", "--plan", "--set", "main"])).is_err());
    }

    #[test]
    fn a_built_in_add_on_and_a_bad_name_are_refused() {
        let builtin = crate::commands::addons::ADDON_ROWS[0].key;
        let (code, msg, hint) = refusal(builtin).expect("a built-in add-on has its own path");
        assert_eq!(code, "builtin");
        assert!(msg.contains("own path"), "{msg}");
        assert_eq!(hint.as_deref(), Some(format!("noo addons enable {builtin}").as_str()));
        assert_eq!(refusal("Not A Name").map(|r| r.0), Some("bad_name"));
        assert_eq!(refusal("-lead").map(|r| r.0), Some("bad_name"));
        assert!(refusal("rhaddon").is_none());
    }

    // ── steps 1 to 3 ──

    #[test]
    fn an_untrusted_add_on_is_a_trust_decision_and_nothing_is_fetched() {
        let root = install("untrusted", false, false);
        let fake = Fake::new().bundle(|| panic!("the bundle must not be read before a key is trusted"));
        let steps = plan(&fake, &root, &opts());
        let t = st(&steps, "trust");
        assert_eq!(t.state, State::Decision);
        assert_eq!(t.command.as_deref(), Some("noo addons trust-key rhaddon <pubkey> --registry <root>"));
        assert_eq!(st(&steps, "bundle").state, State::Blocked);
        assert_eq!(st(&steps, "enable").state, State::Blocked);
        assert!(fake.asked.borrow().is_empty());
    }

    #[test]
    fn a_trusted_key_is_done_and_the_bundle_is_read() {
        let root = install("trusted", true, false);
        let steps = plan(&Fake::new(), &root, &opts());
        assert_eq!(st(&steps, "trust").state, State::Done);
        let b = st(&steps, "bundle");
        assert_eq!(b.state, State::Done);
        assert!(b.detail.contains("version 1.0.0") && b.detail.contains("1 node workload"), "{}", b.detail);
    }

    #[test]
    fn a_registry_refusal_of_access_stops_at_the_login_step() {
        let root = install("auth", true, false);
        let steps = plan(&Fake::new().bundle(|| Err(auth_refusal())), &root, &opts());
        assert_eq!(st(&steps, "trust").state, State::Done);
        assert_eq!(st(&steps, "bundle").state, State::Blocked);
        let login = st(&steps, "registry-login");
        assert_eq!(login.state, State::Stopped);
        assert_eq!(
            login.command.as_deref(),
            Some(format!("noo addons registry-login rhaddon --registry {} --from-file <path>", rt::ROOT).as_str())
        );
        assert_eq!(st(&steps, "enable").state, State::Blocked);
        assert_eq!(st(&steps, "workloads").state, State::Blocked);
    }

    #[test]
    fn any_other_refusal_stops_the_bundle_with_its_fix_and_blocks_the_rest() {
        let root = install("refused", true, false);
        let bad = || Err(Refusal::Lock(addon_lock::AddonLockError::BadSignature("x".into())));
        let steps = plan(&Fake::new().bundle(bad), &root, &opts());
        let b = st(&steps, "bundle");
        assert_eq!(b.state, State::Stopped);
        assert!(b.detail.contains("not signed by a key you trust"), "{}", b.detail);
        assert_eq!(b.command.as_deref(), Some("noo addons trust-key rhaddon <pubkey> --registry <root>"));
        assert!(steps.iter().all(|s| s.id != "registry-login"), "only an auth refusal asks for a login");
        assert_eq!(st(&steps, "enable").state, State::Blocked);
        assert_eq!(st(&steps, "workloads").state, State::Blocked);
    }

    #[test]
    fn an_install_with_no_stack_tag_stops_at_the_bundle() {
        let root = install("notag", true, false);
        std::fs::remove_file(root.join(".env")).unwrap();
        let steps = plan(&Fake::new().bundle(|| panic!("no stack, no fetch")), &root, &opts());
        let b = st(&steps, "bundle");
        assert_eq!(b.state, State::Stopped);
        assert_eq!(b.command.as_deref(), Some("noo upgrade --stack"));
    }

    #[test]
    fn enable_is_todo_until_the_add_on_is_declared_on_and_pinned() {
        let root = install("enable-todo", true, false);
        let steps = plan(&Fake::new(), &root, &opts());
        let e = st(&steps, "enable");
        assert_eq!(e.state, State::Todo);
        assert_eq!(e.command.as_deref(), Some("noo addons enable rhaddon"));
        // Declared on but never pinned is still todo.
        let root = install("enable-unpinned", true, true);
        assert_eq!(st(&plan(&Fake::new(), &root, &opts()), "enable").state, State::Todo);
        // Pinned but not declared on.
        let root = install("enable-undeclared", true, false);
        pin(&root, "1.0.0");
        let e = st(&plan(&Fake::new(), &root, &opts()), "enable").clone();
        assert_eq!(e.state, State::Todo);
        assert!(e.detail.contains("not declared on"), "{}", e.detail);
    }

    #[test]
    fn enable_is_done_when_declared_on_and_pinned_at_the_offered_version() {
        let root = install("enable-done", true, true);
        pin(&root, "1.0.0");
        let steps = plan(&Fake::new(), &root, &opts());
        assert_eq!(st(&steps, "enable").state, State::Done);
    }

    #[test]
    fn enable_is_todo_when_the_pin_is_older_than_the_offered_bundle() {
        let root = install("enable-older", true, true);
        pin(&root, "1.0.0");
        let steps = plan(&Fake::new().bundle(|| good_bundle("1.1.0")), &root, &opts());
        let e = st(&steps, "enable");
        assert_eq!(e.state, State::Todo);
        assert!(e.detail.contains("pinned at 1.0.0") && e.detail.contains("offers 1.1.0"), "{}", e.detail);
        assert_eq!(e.command.as_deref(), Some("noo addons upgrade rhaddon"));
    }

    #[test]
    fn a_bundle_without_node_workloads_ends_the_plan_after_enable() {
        let root = install("no-workloads", true, true);
        let fake = Fake::new().bundle(plain_bundle).sets(vec![voice("rh-voice")]);
        let steps = plan(&fake, &root, &opts());
        assert_eq!(ids(&steps), ["trust", "bundle", "enable"]);
        assert!(fake.asked.borrow().is_empty(), "no gateway question for an add-on with no workload");
    }

    // ── steps 4 and 5 ──

    fn plan_sets(name: &str, fake: Fake, o: Opts) -> Vec<Step> {
        plan(&fake, &install(name, true, true), &o)
    }

    #[test]
    fn a_slot_with_no_staged_set_is_stopped_with_a_stage_template() {
        let steps = plan_sets("sets-none", Fake::new(), opts());
        let s = st(&steps, "sets:main");
        assert_eq!(s.state, State::Stopped);
        let c = s.command.as_deref().unwrap();
        assert!(c.starts_with("noo models stage <hf:repo@sha>") && c.contains("--kind voice") && c.contains("--runtime rh-s2s"), "{c}");
        // The optional slot is skipped, not stopped.
        assert_eq!(st(&steps, "sets:voices").state, State::Done);
        assert!(st(&steps, "sets:voices").detail.contains("skipped"));
        // Nothing after the stopped slot is attempted.
        for id in ["place", "consent", "delivery", "reserve"] {
            assert_eq!(st(&steps, id).state, State::Blocked, "{id}");
        }
    }

    #[test]
    fn a_set_of_the_wrong_kind_or_runtime_or_unsigned_does_not_count() {
        let mut unsigned = voice("rh-unsigned");
        unsigned.usable = false;
        let sets = vec![staged("a", "r1", "voice-pack", "rh-s2s"), staged("b", "r1", "voice", "other-runtime"), unsigned];
        let steps = plan_sets("sets-misfit", Fake::new().sets(sets), opts());
        assert_eq!(st(&steps, "sets:main").state, State::Stopped);
    }

    #[test]
    fn one_matching_set_is_chosen_and_many_are_a_decision_until_set_names_one() {
        let one = plan_sets("sets-one", Fake::new().sets(vec![voice("rh-voice")]), opts());
        let s = st(&one, "sets:main");
        assert_eq!(s.state, State::Done);
        assert!(s.detail.contains("rh-voice@r1"), "{}", s.detail);

        let two = vec![voice("rh-voice"), voice("rh-voice-2")];
        let many = plan_sets("sets-many", Fake::new().sets(two.clone()), opts());
        let d = st(&many, "sets:main");
        assert_eq!(d.state, State::Decision);
        assert!(d.detail.contains("rh-voice@r1") && d.detail.contains("rh-voice-2@r1"), "{}", d.detail);
        assert_eq!(d.command.as_deref(), Some("noo addons setup rhaddon --plan --set main=<id>@<rev>"));

        let mut o = opts();
        o.sets.push(parse_set("main=rh-voice-2@r1").unwrap());
        let chosen = plan_sets("sets-named", Fake::new().sets(two.clone()), o);
        let c = st(&chosen, "sets:main");
        assert_eq!(c.state, State::Done);
        assert!(c.detail.contains("rh-voice-2@r1") && c.detail.contains("--set"), "{}", c.detail);

        // A --set naming a set that is not staged is stopped, never trusted.
        let mut o = opts();
        o.sets.push(parse_set("main=ghost@r9").unwrap());
        let bad = plan_sets("sets-ghost", Fake::new().sets(two), o);
        assert_eq!(st(&bad, "sets:main").state, State::Stopped);

        // A --set for a slot the bundle does not declare is stopped too.
        let mut o = opts();
        o.sets.push(parse_set("nowhere=x@r1").unwrap());
        let extra = plan_sets("sets-extra", Fake::new().sets(vec![voice("rh-voice")]), o);
        assert_eq!(st(&extra, "sets:nowhere").state, State::Stopped);
    }

    #[test]
    fn a_licence_that_needs_the_operator_is_a_decision_with_the_accept_line() {
        let mut open = voice("rh-voice");
        open.licence_open = true;
        let steps = plan_sets("licence-open", Fake::new().sets(vec![open]), opts());
        let l = st(&steps, "licence:rh-voice");
        assert_eq!(l.state, State::Decision);
        assert_eq!(l.command.as_deref(), Some("noo models accept rh-voice"));

        let steps = plan_sets("licence-done", Fake::new().sets(vec![voice("rh-voice")]), opts());
        assert_eq!(st(&steps, "licence:rh-voice").state, State::Done);
        assert!(steps.iter().all(|s| s.id != "licence:rh-voice" || s.command.is_none()));
    }

    // ── steps 6 to 9 ──

    #[test]
    fn everything_done_reads_done_from_trust_to_reserve() {
        let (fake, root) = happy("happy");
        let steps = plan(&fake, &root, &opts());
        for s in &steps {
            assert_eq!(s.state, State::Done, "{}: {}", s.id, s.detail);
        }
        assert_eq!(
            ids(&steps),
            ["trust", "bundle", "enable", "sets:main", "sets:voices", "licence:rh-voice", "place", "consent", "delivery", "reserve"]
        );
    }

    #[test]
    fn an_unreachable_gateway_makes_steps_six_to_nine_unknown_not_a_failed_plan() {
        let root = install("gw-down", true, true);
        pin(&root, "1.0.0");
        let steps = plan(&Fake::new().sets(vec![voice("rh-voice")]), &root, &opts());
        assert_eq!(st(&steps, "enable").state, State::Done, "the steps that need no gateway still read");
        for id in ["place", "consent", "delivery", "reserve"] {
            let s = st(&steps, id);
            assert_eq!(s.state, State::Unknown, "{id}");
            assert!(s.detail.contains("gateway unreachable"), "{}", s.detail);
        }
    }

    #[test]
    fn a_workload_placed_nowhere_is_a_node_decision_unless_node_names_one() {
        let nodes = nodes_body(Some("approve"), Some(approved()), Some(verified()));
        let empty = json!({"node_id": NODE, "node_workloads": []});
        let root = install("place-decision", true, true);
        let fake = Fake::new().sets(vec![voice("rh-voice")]).gw(NODES, nodes.clone()).gw(PLACED, empty.clone());
        let steps = plan(&fake, &root, &opts());
        let p = st(&steps, "place");
        assert_eq!(p.state, State::Decision);
        assert!(p.detail.contains("node-a"), "{}", p.detail);
        assert_eq!(st(&steps, "consent").state, State::Blocked);

        let mut o = opts();
        o.node = Some(NODE.into());
        let fake = Fake::new().sets(vec![voice("rh-voice")]).gw(NODES, nodes).gw(PLACED, empty).gw(RESERVATIONS, reservations(json!([])));
        let steps = plan(&fake, &root, &o);
        let p = st(&steps, "place");
        assert_eq!(p.state, State::Todo);
        assert_eq!(p.command.as_deref(), Some("noo cluster workloads place node-a rhaddon/worker --set main=rh-voice@r1"));
        assert_eq!(st(&steps, "consent").state, State::Done, "consent is read from the node, placed or not");
        assert_eq!(st(&steps, "delivery").state, State::Blocked);
        assert_eq!(st(&steps, "reserve").state, State::Blocked);

        let mut o = opts();
        o.node = Some("ghost".into());
        let fake = Fake::new().sets(vec![voice("rh-voice")]).gw(NODES, nodes_body(None, None, None));
        let steps = plan(&fake, &root, &o);
        assert_eq!(st(&steps, "place").state, State::Stopped);
    }

    #[test]
    fn a_placement_with_other_sets_is_todo_with_the_place_line() {
        let (fake, root) = happy("place-other");
        let fake = fake.gw(PLACED, placement(json!({"main": [{"id": "old-voice", "revision": "r1"}]})));
        let steps = plan(&fake, &root, &opts());
        let p = st(&steps, "place");
        assert_eq!(p.state, State::Todo);
        assert!(p.detail.contains("old-voice@r1") && p.detail.contains("rh-voice@r1"), "{}", p.detail);
        assert!(p.command.as_deref().unwrap().contains("--set main=rh-voice@r1"));
    }

    #[test]
    fn consent_is_done_only_when_the_nodes_approvals_hold_this_digest() {
        let root = install("consent", true, true);
        pin(&root, "1.0.0");
        let with = |approvals: Option<Value>, policy: Option<&str>| {
            Fake::new()
                .sets(vec![voice("rh-voice")])
                .gw(NODES, nodes_body(policy, approvals, Some(verified())))
                .gw(PLACED, placed_main())
                .gw(RESERVATIONS, held())
        };
        let consent = |f: Fake| st(&plan(&f, &root, &opts()), "consent").clone();

        let ok = consent(with(Some(approved()), Some("approve")));
        assert_eq!(ok.state, State::Done, "{}", ok.detail);

        // Approved at another digest: not this image.
        let other = json!([{"addon": "rhaddon", "digest": rt::digest('9')}]);
        let c = consent(with(Some(other), Some("approve")));
        assert_eq!(c.state, State::Stopped, "{}", c.detail);
        assert_eq!(
            c.command.as_deref(),
            Some(format!("on node-a, run: sudo \"$(command -v noo)\" node workloads approve rhaddon {}", image_digest()).as_str())
        );
        assert!(!c.command.as_deref().unwrap().contains("cluster workloads approve"), "the controller-side verb is not on this branch");

        // The right digest for another add-on is not consent for this one.
        let c = consent(with(Some(json!([{"addon": "someone-else", "digest": image_digest()}])), Some("approve")));
        assert_eq!(c.state, State::Stopped);

        // No approvals at all.
        assert_eq!(consent(with(Some(json!([])), Some("approve"))).state, State::Stopped);
        // Approvals not reported: unknown, not a refusal.
        assert_eq!(consent(with(None, Some("approve"))).state, State::Unknown);
        // The owner's other two settings.
        assert_eq!(consent(with(None, Some("auto"))).state, State::Done);
        let none = consent(with(None, Some("none")));
        assert_eq!(none.state, State::Stopped);
        assert!(none.command.as_deref().unwrap().contains("switched add-on node workloads off"));
        assert_eq!(consent(with(None, None)).state, State::Unknown);
    }

    #[test]
    fn a_controller_approval_counts_and_says_who_gave_it() {
        let root = install("consent-ctl", true, true);
        pin(&root, "1.0.0");
        let ctl = json!([{"addon": "rhaddon", "digest": image_digest(), "source": "controller"}]);
        let fake = Fake::new()
            .sets(vec![voice("rh-voice")])
            .gw(NODES, nodes_body(Some("approve"), Some(ctl), Some(verified())))
            .gw(PLACED, placed_main())
            .gw(RESERVATIONS, held());
        let c = st(&plan(&fake, &root, &opts()), "consent").clone();
        assert_eq!(c.state, State::Done);
        assert!(c.detail.contains("the controller"), "{}", c.detail);
    }

    #[test]
    fn delivery_shows_the_state_and_reason_until_every_set_is_verified() {
        let root = install("delivery", true, true);
        pin(&root, "1.0.0");
        let with = |model_sets: Option<Value>| {
            Fake::new()
                .sets(vec![voice("rh-voice")])
                .gw(NODES, nodes_body(Some("approve"), Some(approved()), model_sets))
                .gw(PLACED, placed_main())
                .gw(RESERVATIONS, held())
        };
        let delivery = |f: Fake| st(&plan(&f, &root, &opts()), "delivery").clone();

        let d = delivery(with(Some(json!([{"id": "rh-voice", "revision": "r1", "state": "failed", "reason": "digest_mismatch"}]))));
        assert_eq!(d.state, State::Todo);
        assert!(d.detail.contains("rh-voice@r1: failed (digest_mismatch)"), "{}", d.detail);
        let d = delivery(with(Some(json!([{"id": "rh-voice", "revision": "r1", "state": "fetching"}]))));
        assert_eq!(d.state, State::Todo);
        assert!(d.detail.contains("fetching"));
        let d = delivery(with(Some(json!([]))));
        assert_eq!(d.state, State::Todo);
        assert!(d.detail.contains("not on the node yet"));
        assert_eq!(delivery(with(None)).state, State::Unknown, "a node that does not report is unknown, not empty");
        assert_eq!(delivery(with(Some(verified()))).state, State::Done);
    }

    #[test]
    fn reserve_is_done_only_with_a_reservation_for_this_workload() {
        let root = install("reserve", true, true);
        pin(&root, "1.0.0");
        let with = |res: Value| {
            Fake::new()
                .sets(vec![voice("rh-voice")])
                .gw(NODES, nodes_body(Some("approve"), Some(approved()), Some(verified())))
                .gw(PLACED, placed_main())
                .gw(RESERVATIONS, res)
        };
        let reserve = |f: Fake| st(&plan(&f, &root, &opts()), "reserve").clone();

        assert_eq!(reserve(with(held())).state, State::Done);
        let r = reserve(with(reservations(json!([]))));
        assert_eq!(r.state, State::Todo);
        assert_eq!(r.command.as_deref(), Some("noo cluster reserve rhaddon/worker --node node-a"));
        let other = reservations(json!([{"id": "res-2", "workload": "rhaddon/other", "node": NODE, "state": "held"}]));
        assert_eq!(reserve(with(other)).state, State::Todo, "another workload's reservation is not this one");
        assert_eq!(reserve(with(json!({}))).state, State::Unknown);
    }

    // ── the planner changes nothing ──

    fn snapshot(dir: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                let rel = p.strip_prefix(base).unwrap().display().to_string();
                if p.is_dir() {
                    out.insert(rel, None);
                    walk(base, &p, out);
                } else {
                    out.insert(rel, Some(std::fs::read(&p).unwrap()));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(dir, dir, &mut out);
        out
    }

    #[test]
    fn planning_writes_nothing_under_the_root() {
        let (fake, root) = happy("no-writes");
        let before = snapshot(&root);
        assert!(before.keys().any(|k| k.starts_with("addons")), "the root holds a pinned add-on: {before:?}");
        let steps = plan(&fake, &root, &opts());
        assert_eq!(st(&steps, "enable").state, State::Done);
        assert_eq!(snapshot(&root), before, "the root changed");
        // Also with nothing pinned or trusted, and with a refusal.
        let bare = install("no-writes-bare", true, false);
        let before = snapshot(&bare);
        plan(&Fake::new().bundle(|| Err(auth_refusal())), &bare, &opts());
        plan(&Fake::new(), &bare, &opts());
        assert_eq!(snapshot(&bare), before, "the root changed");
    }

    #[test]
    fn the_planner_only_asks_the_gateway_with_get_paths_it_knows() {
        let (fake, root) = happy("asked");
        plan(&fake, &root, &opts());
        let asked = fake.asked.borrow();
        for p in asked.iter() {
            assert!([NODES, PLACED, RESERVATIONS].contains(&p.as_str()), "unexpected gateway path {p}");
        }
        assert!(asked.iter().any(|p| p == RESERVATIONS));
    }

    #[test]
    fn the_planner_source_calls_nothing_that_writes() {
        let src = crate::test_src::own_code(include_str!("addon_setup.rs"));
        for f in ["pub(crate) fn plan(", "fn enable_step(", "fn plan_workload(", "fn gateway_steps(", "fn slot_step("] {
            let body = crate::test_src::fn_body(&src, f);
            for bad in ["fs::write", "set_pin", "resolve::record", "materialise", "addons::commit", "prepare_from", "create_dir", "remove_", "rename(", "post_json", "put_json", "delete_json", "request_status"] {
                assert!(!body.contains(bad), "{f} calls {bad}");
            }
        }
    }

    // ── output ──

    #[test]
    fn the_json_carries_each_step_with_its_state_detail_and_command() {
        let steps = vec![
            step("trust", State::Done, "ok", None),
            step("enable", State::Todo, "later", Some("noo addons enable rhaddon".to_string())),
        ];
        let j = plan_json("rhaddon", &steps);
        assert_eq!(j["addon"], "rhaddon");
        assert_eq!(j["steps"][0], json!({"step": "trust", "state": "done", "detail": "ok", "command": null}));
        assert_eq!(j["steps"][1]["state"], "todo");
        assert_eq!(j["steps"][1]["command"], "noo addons enable rhaddon");
        for s in [State::Done, State::Todo, State::Decision, State::Stopped, State::Blocked, State::Unknown] {
            assert!(["done", "todo", "decision", "stopped", "blocked", "unknown"].contains(&s.word()));
        }
    }

    #[test]
    fn step_labels_name_the_slot_set_and_workload() {
        assert_eq!(label("sets:main"), "Model set for main");
        assert_eq!(label("licence:rh-voice"), "Licence of rh-voice");
        assert_eq!(label("place@worker"), "Place the workload (worker)");
        assert_eq!(label("registry-login"), "Log in to the registry");
    }
}
