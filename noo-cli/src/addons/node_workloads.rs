// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! An add-on bundle's `node-workloads.json` (`noo-addon-node-workloads/1`),
//! i300: the workloads a node runs for the add-on, beside the controller-side
//! `workloads.json` of [`super::decls`].
//!
//! This is the CLI's validator of the i300 contract
//! (`docs/reference/node-workloads.md`). The node agent
//! (`node-agent-go/internal/nodewl`) and the gateway each validate the SAME
//! fixtures, `tests/fixtures/i300`, of which `testdata/i300` beside this file
//! is a byte-identical copy (`tests/test_i300_fixture_parity.py`). Every
//! refusal carries a stable code equal to the agent's, and the tests below
//! hold this parser to `cases.json`: same verdict, same code, for every file.
//! The checks run in the agent's order (`decl.go`), so a file with two defects
//! gets the same code here as there.
//!
//! The first step is a duplicate-key pass over the raw bytes at any depth:
//! serde's derived structs refuse a repeated field, but a map (`env`) or a
//! `Value` keeps the last one silently, and a validator and a runtime that
//! read different values of one key is a parser differential.

// Consumers (i300 F2c): `decls::check_node_workloads` calls
// `parse_node_workloads` at enable, upgrade (`--check` too), verify and
// launch, and `node_images` reads the validated `image` names. What nothing
// outside the tests reads yet carries its own `allow(dead_code)` below: the
// refusal's `code`/`message` accessors (the callers print the Display form),
// the model-slot and realtime fields (the node agent's, not the CLI's), and
// `node_workload_doors`, which harness H6's door-leaf issuance plugs into.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;

pub const NODE_WORKLOADS_FILE: &str = "node-workloads.json";
/// The `format` of node-workloads.json.
pub const NODE_WORKLOADS_FORMAT: &str = "noo-addon-node-workloads/1";

/// `noo-stunnel-<addon>-<workload>` is one DNS label of at most 63 characters;
/// "noo-stunnel-" is 12 and the joining "-" 1, so
/// `len(addon) + 1 + len(workload)` is at most 51.
const MAX_DOOR_NAMES: usize = 51;
const MAX_WORKLOADS_PER_FILE: usize = 16;
const NOT_AT_ENDS: &str = "not at either end";

/// Prefixes no declared env key may start with, whatever the add-on is called.
/// `tests/test_i300_fixture_parity.py` holds this list to the agent's.
const REFUSED_ENV_PREFIXES: &[&str] =
    &["NOO_", "NVIDIA_", "CUDA_", "LD_", "PYTHON", "HF_", "TRANSFORMERS_"];

/// A refusal: a stable `code` (what the fixtures pin; equal to the node
/// agent's) and a message for a human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWorkloadRefusal {
    code: &'static str,
    message: String,
}

// Read by the fixture tests; the lifecycle prints the Display form.
#[cfg_attr(not(test), allow(dead_code))]
impl NodeWorkloadRefusal {
    pub fn code(&self) -> &str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for NodeWorkloadRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

fn refuse(code: &'static str, message: String) -> NodeWorkloadRefusal {
    NodeWorkloadRefusal { code, message }
}

/// One validated workload. Same fields, names and meaning as the agent's
/// `nodewl.Decl`. A field the file leaves out takes its default here and is
/// caught as `field_missing` (or by its range rule) before a value is handed
/// out.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeWorkload {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub uid: i64,
    pub command: Option<Vec<String>>,
    #[serde(default)]
    pub port: i64,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub health: Health,
    #[serde(default)]
    pub drain: Drain,
    /// Absent is `service_drain_invalid` (not `field_missing`), as in the
    /// agent, where the field is a pointer.
    pub service_drain: Option<ServiceDrain>,
    #[serde(default)]
    pub accel: Accel,
    #[serde(default)]
    pub models: Vec<Slot>,
    #[serde(default)]
    pub env: BTreeMap<String, EnvBound>,
    #[serde(default)]
    pub scratch: Vec<Scratch>,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    #[serde(default)]
    pub ready: String,
    #[serde(default)]
    pub live: String,
    #[serde(default)]
    pub start_secs: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Drain {
    #[serde(default)]
    pub path: String,
    /// GET path the agent polls: 200 means drained. Required (a bad one is
    /// `drain_invalid`, as in `nodewl.Drain`).
    #[serde(default)]
    pub done_path: String,
    #[serde(default)]
    pub timeout_secs: i64,
}

/// A route NAME in the add-on's `routes.json` (never a path, never inferred)
/// and how long the gateway waits for it. Same as the agent's
/// `nodewl.ServiceDrain`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDrain {
    #[serde(default)]
    pub route: String,
    #[serde(default)]
    pub timeout_secs: i64,
}

// `realtime` is the node agent's to read; the CLI only validates the file.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accel {
    #[serde(default)]
    pub gpu: i64,
    #[serde(default)]
    pub realtime: bool,
    /// The declared integer env key that sets the worker's slot count.
    #[serde(default)]
    pub slots_env: String,
}

/// A model slot: the agent mounts the set the operator chose, read-only, at
/// `target`.
// `many` and `optional` are the node agent's to read, not the CLI's.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    #[serde(default)]
    pub slot: String,
    #[serde(default)]
    pub target: String,
    pub accepts: Option<Accepts>,
    #[serde(default)]
    pub many: bool,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accepts {
    #[serde(default)]
    pub kind: String,
    pub runtime: Option<String>,
}

/// Bounds one declared env key: an integer range (`min` and/or `max`) or an
/// enum (`one_of`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvBound {
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub one_of: Option<Vec<String>>,
}

/// Writable space: a size-capped named volume (`max_mb`) or a tmpfs
/// (`tmpfs_mb`), exactly one of the two.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scratch {
    #[serde(default)]
    pub target: String,
    pub max_mb: Option<i64>,
    pub tmpfs_mb: Option<i64>,
    /// A12: the one scratch the worker may load native code from.
    #[serde(default)]
    pub exec: bool,
}

/// The size cap of the exec scratch, in MiB.
pub const MAX_EXEC_SCRATCH_MB: i64 = 1024;

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default)]
    pub ram_mb: i64,
    #[serde(default)]
    pub cpus: f64,
    #[serde(default)]
    pub pids: i64,
}

/// The file itself. A workload stays a `Value` here: the agent reads the
/// file level first (format, count) and each workload after, so an unknown
/// field inside a workload is only reported once the file level has passed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    format: Option<String>,
    workloads: Option<Vec<Value>>,
}

/// What the raw-bytes walk found. serde_json's error type carries only text,
/// so the repeated key is parked here.
#[derive(Default)]
struct Found {
    dup: RefCell<Option<String>>,
    null: Cell<bool>,
}

/// Walks a JSON document and fails at the first object that repeats a key,
/// at any depth. It also notes a JSON `null`: this contract names no nullable
/// field, so a null is `field_type` wherever it stands (a field may be absent,
/// never null). Like the agent's walk it stops at the first of the two in
/// document order.
#[derive(Clone, Copy)]
struct NoDup<'a>(&'a Found);

impl<'de> DeserializeSeed<'de> for NoDup<'_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for NoDup<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, _v: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _v: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _v: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _v: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _v: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        self.0.null.set(true);
        Err(E::custom("null"))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(self)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        while let Some(k) = map.next_key::<String>()? {
            if !seen.insert(k.clone()) {
                *self.0.dup.borrow_mut() = Some(k);
                return Err(<A::Error as de::Error>::custom("duplicate key"));
            }
            map.next_value_seed(self)?;
        }
        Ok(())
    }
}

/// Walks `bytes` once: the first key an object repeats, at any depth, and
/// whether a `null` ended the walk. Bytes that are not JSON
/// are not its business: the typed decode that follows reports them.
fn walk(bytes: &[u8]) -> Found {
    let found = Found::default();
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let _ = NoDup(&found).deserialize(&mut de);
    found
}

/// The first key an object of `bytes` repeats, at any depth. Only the tests
/// ask for the key alone; parse_node_workloads reads the walk directly.
#[cfg(test)]
fn find_duplicate_key(bytes: &[u8]) -> Option<String> {
    walk(bytes).dup.into_inner()
}

/// What a failed typed decode is: an unknown field, a value of the wrong
/// type, or (not JSON, data after the document, empty input) `bad_json`.
fn decode_refusal(what: &str, e: &serde_json::Error) -> NodeWorkloadRefusal {
    if !e.is_data() {
        return refuse("bad_json", format!("{what}: {e}"));
    }
    if e.to_string().starts_with("unknown field") {
        refuse("unknown_field", format!("{what}: {e}"))
    } else {
        refuse("field_type", format!("{what}: {e}"))
    }
}

/// `field_missing` when `v` is an object that lacks one of `keys`. Anything
/// that is not an object is left to the typed decode.
fn missing_key(v: &Value, what: &str, keys: &[&str]) -> Option<NodeWorkloadRefusal> {
    let m = v.as_object()?;
    for k in keys {
        if !m.contains_key(*k) {
            return Some(refuse("field_missing", format!("{what}: `{k}` is required")));
        }
    }
    None
}

/// Required keys of the objects inside a workload, checked after the
/// workload's own, in this order.
const REQUIRED_SUBKEYS: &[(&str, &[&str])] = &[
    ("health", &["ready", "live", "start_secs"]),
    ("drain", &["path", "timeout_secs"]),
    ("accel", &["gpu"]),
    ("limits", &["ram_mb", "cpus", "pids"]),
];

/// The add-on's `routes.json` as `name -> internal?`, the input of
/// [`parse_node_workloads`]'s cross-file rule (the agent's
/// `nodewl.RoutesFromJSON`). It reuses the reader of `workloads.json`'s
/// `drain.route` check. A `routes.json` that cannot be read gives an empty
/// map, so every `service_drain.route` is then unknown and refused: the gateway
/// refuses such a manifest on its own, and the CLI never lets it through.
pub fn routes_from_json(bytes: &[u8]) -> BTreeMap<String, bool> {
    super::decls::route_kinds(bytes).unwrap_or_default()
}

/// Parse and validate the `node-workloads.json` of `addon`. `lock_images` is
/// the `images` map of the add-on's verified lock (name -> ref): a workload's
/// `image` must be a key of it. `routes` is the add-on's `routes.json` from
/// [`routes_from_json`]: `service_drain.route` must be an internal route of
/// it. `None` skips ONLY that existence and internal check; the shape of
/// `service_drain` is always checked. The first refusal wins; the fixtures
/// carry one defect each. Same checks, same order and same codes as the node
/// agent's `nodewl.ParseDecl`.
pub fn parse_node_workloads(
    addon: &str,
    bytes: &[u8],
    lock_images: &BTreeMap<String, String>,
    routes: Option<&BTreeMap<String, bool>>,
) -> Result<Vec<NodeWorkload>, NodeWorkloadRefusal> {
    let found = walk(bytes);
    if let Some(k) = found.dup.into_inner() {
        return Err(refuse("duplicate_key", format!("key `{k}` is repeated in an object")));
    }
    if found.null.get() {
        return Err(refuse(
            "field_type",
            format!("{NODE_WORKLOADS_FILE}: null is not a value here (leave the field out)"),
        ));
    }
    // Syntax first, over the whole input, as Go's json.Unmarshal does: a
    // truncated document (`[1, 2`) is bad_json, not the type error a typed
    // decode would hit before it reached the end.
    if let Err(e) = serde_json::from_slice::<serde::de::IgnoredAny>(bytes) {
        return Err(refuse("bad_json", format!("{NODE_WORKLOADS_FILE}: {e}")));
    }
    let file: File = serde_json::from_slice(bytes)
        .map_err(|e| decode_refusal(NODE_WORKLOADS_FILE, &e))?;
    let (Some(format), Some(raws)) = (file.format, file.workloads) else {
        let what = if file_has_format(bytes) { "workloads" } else { "format" };
        return Err(refuse(
            "field_missing",
            format!("{NODE_WORKLOADS_FILE}: `{what}` is required"),
        ));
    };
    if format != NODE_WORKLOADS_FORMAT {
        return Err(refuse(
            "bad_format",
            format!("format is `{format}`, want `{NODE_WORKLOADS_FORMAT}`"),
        ));
    }
    if raws.is_empty() || raws.len() > MAX_WORKLOADS_PER_FILE {
        return Err(refuse(
            "workloads_invalid",
            format!("{} workloads (1..={MAX_WORKLOADS_PER_FILE})", raws.len()),
        ));
    }
    let mut out: Vec<NodeWorkload> = Vec::with_capacity(raws.len());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (i, raw) in raws.into_iter().enumerate() {
        let w = parse_workload(addon, raw, lock_images, routes)?;
        if !seen.insert(w.name.clone()) {
            return Err(refuse(
                "name_duplicate",
                format!("workloads[{i}]: name `{}` is declared twice", w.name),
            ));
        }
        out.push(w);
    }
    Ok(out)
}

/// Whether the top-level object has a `format` key. Only used to name the
/// missing one: the agent checks `format` before `workloads`.
fn file_has_format(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| v.as_object().map(|m| m.contains_key("format")))
        .unwrap_or(false)
}

fn parse_workload(
    addon: &str,
    raw: Value,
    lock_images: &BTreeMap<String, String>,
    routes: Option<&BTreeMap<String, bool>>,
) -> Result<NodeWorkload, NodeWorkloadRefusal> {
    // The agent decodes first (unknown field, type), then looks for missing
    // keys; the keys are read off the Value before the decode consumes it.
    let missing = missing_key(
        &raw,
        "workload",
        &[
            "name", "image", "uid", "port", "protocols", "health", "drain", "accel", "limits",
        ],
    )
    .or_else(|| {
        REQUIRED_SUBKEYS
            .iter()
            .find_map(|(name, keys)| raw.get(*name).and_then(|sub| missing_key(sub, name, keys)))
    });
    let w: NodeWorkload =
        serde_json::from_value(raw).map_err(|e| decode_refusal("workload", &e))?;
    if let Some(m) = missing {
        return Err(m);
    }
    validate(addon, &w, lock_images, routes)?;
    Ok(w)
}

// ---- the character classes of the agent's regexps, written out ------------
// noo-cli carries no regex crate. Each fn is one regexp of decl.go; lengths
// are in bytes, as Go's are, and every class is ASCII.

fn is_lower_digit(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`
fn door_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    match (b.first(), b.last()) {
        (Some(f), Some(l)) => {
            is_lower_digit(*f)
                && is_lower_digit(*l)
                && b.iter().all(|c| is_lower_digit(*c) || *c == b'-')
        }
        _ => false,
    }
}

/// `^[a-z][a-z0-9-]{0,31}$`
fn word_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| is_lower_digit(*c) || *c == b'-')
}

/// `^/[A-Za-z0-9._~/-]*$`, at most 128 bytes.
fn path_ok(s: &str) -> bool {
    s.len() <= 128
        && s.starts_with('/')
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._~/-".contains(&c))
}

/// `^/[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`
fn target_shape_ok(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('/') else {
        return false;
    };
    rest.split('/').all(|seg| {
        let b = seg.as_bytes();
        !b.is_empty()
            && (b[0].is_ascii_alphanumeric() || b[0] == b'_' || b[0] == b'-')
            && b.iter().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c))
    })
}

/// `^[a-z][a-z0-9_]{0,63}$`
fn route_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| is_lower_digit(*c) || *c == b'_')
}

/// `^[a-z0-9][a-z0-9._-]{0,63}$`
fn runtime_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && is_lower_digit(b[0])
        && b.iter().all(|c| is_lower_digit(*c) || b"._-".contains(c))
}

/// `^[A-Z][A-Z0-9_]{0,63}$`
fn env_key_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && b[0].is_ascii_uppercase()
        && b.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

/// `^[A-Za-z0-9._:-]{1,64}$`
fn enum_val_ok(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
}

/// The prefix every env key of `addon` must carry: the name upper-cased,
/// `-` as `_`.
pub fn env_prefix(addon: &str) -> String {
    format!("{}_", addon.to_ascii_uppercase().replace('-', "_"))
}

/// `/`, `/proc`, `/sys`, `/dev` and anything under the last three.
fn refused_target(t: &str) -> bool {
    t == "/"
        || ["/proc", "/sys", "/dev"]
            .iter()
            .any(|r| t.strip_prefix(*r).is_some_and(|rest| rest.is_empty() || rest.starts_with('/')))
}

fn under(a: &str, b: &str) -> bool {
    a.strip_prefix(b).is_some_and(|rest| rest.starts_with('/'))
}

fn overlaps(a: &str, b: &str) -> bool {
    a == b || under(a, b) || under(b, a)
}

fn validate(
    addon: &str,
    d: &NodeWorkload,
    lock_images: &BTreeMap<String, String>,
    routes: Option<&BTreeMap<String, bool>>,
) -> Result<(), NodeWorkloadRefusal> {
    if !door_name_ok(addon) {
        return Err(refuse(
            "door_name_invalid",
            format!("add-on name `{addon}` must be lowercase letters, digits and `-`, {NOT_AT_ENDS}"),
        ));
    }
    if !door_name_ok(&d.name) {
        return Err(refuse(
            "door_name_invalid",
            format!("workload name `{}` must be lowercase letters, digits and `-`, {NOT_AT_ENDS}", d.name),
        ));
    }
    let n = addon.len() + 1 + d.name.len();
    if n > MAX_DOOR_NAMES {
        return Err(refuse(
            "door_name_too_long",
            format!(
                "{addon}/{}: len(addon)+1+len(workload) is {n}, at most {MAX_DOOR_NAMES}",
                d.name
            ),
        ));
    }
    if !lock_images.contains_key(d.image.as_str()) || !word_ok(&d.image) {
        return Err(refuse(
            "image_not_in_lock",
            format!("image `{}` is not a name in the lock's images map", d.image),
        ));
    }
    if !(1..=4_294_967_294).contains(&d.uid) {
        return Err(refuse(
            "uid_invalid",
            format!("uid {} (1..4294967294; 0 is refused)", d.uid),
        ));
    }
    if let Some(cmd) = &d.command {
        if !(1..=16).contains(&cmd.len()) {
            return Err(refuse(
                "command_invalid",
                format!("command has {} elements (1..16)", cmd.len()),
            ));
        }
        if cmd.iter().any(|c| c.is_empty() || c.len() > 256) {
            return Err(refuse(
                "command_invalid",
                "a command element is empty or over 256 bytes".to_string(),
            ));
        }
    }
    if !(1024..=65535).contains(&d.port) {
        return Err(refuse("port_invalid", format!("port {} (1024..65535)", d.port)));
    }
    if !(1..=2).contains(&d.protocols.len()) {
        return Err(refuse(
            "protocols_invalid",
            format!("{} protocols (1..2)", d.protocols.len()),
        ));
    }
    if let Some(p) = d.protocols.iter().find(|p| p.as_str() != "http" && p.as_str() != "ws") {
        return Err(refuse("protocols_invalid", format!("protocol `{p}` (http, ws)")));
    }
    if !path_ok(&d.health.ready)
        || !path_ok(&d.health.live)
        || !(1..=600).contains(&d.health.start_secs)
    {
        return Err(refuse(
            "health_invalid",
            "health needs absolute paths and start_secs 1..600".to_string(),
        ));
    }
    if !path_ok(&d.drain.path)
        || !path_ok(&d.drain.done_path)
        || !(1..=3600).contains(&d.drain.timeout_secs)
    {
        return Err(refuse(
            "drain_invalid",
            "drain needs absolute path and done_path, and timeout_secs 1..3600".to_string(),
        ));
    }
    validate_service_drain(d.service_drain.as_ref(), routes)?;
    if !(0..=8).contains(&d.accel.gpu) {
        return Err(refuse("accel_invalid", format!("accel.gpu {} (0..8)", d.accel.gpu)));
    }
    validate_models(&d.models)?;
    validate_env(addon, &d.env)?;
    validate_slots_env(&d.accel.slots_env, &d.env)?;
    validate_scratch(&d.scratch, &d.models)?;
    let l = &d.limits;
    if !(64..=1_048_576).contains(&l.ram_mb)
        || !(0.1..=128.0).contains(&l.cpus)
        || !(1..=32768).contains(&l.pids)
    {
        return Err(refuse(
            "limits_invalid",
            "limits out of range: ram_mb 64..1048576, cpus 0.1..128, pids 1..32768".to_string(),
        ));
    }
    Ok(())
}

fn validate_service_drain(
    s: Option<&ServiceDrain>,
    routes: Option<&BTreeMap<String, bool>>,
) -> Result<(), NodeWorkloadRefusal> {
    let bad = |m: String| refuse("service_drain_invalid", m);
    let Some(s) = s else {
        return Err(bad(
            "`service_drain` is required: the add-on's drain route and timeout".to_string(),
        ));
    };
    if !route_name_ok(&s.route) {
        return Err(bad(format!(
            "service_drain.route `{}` is not a route name ([a-z][a-z0-9_]{{0,63}})",
            s.route
        )));
    }
    if !(1..=3600).contains(&s.timeout_secs) {
        return Err(bad(format!("service_drain.timeout_secs {} (1..3600)", s.timeout_secs)));
    }
    let Some(routes) = routes else {
        return Ok(());
    };
    match routes.get(&s.route) {
        None => Err(bad(format!(
            "service_drain.route `{}` is not a route of the add-on's routes.json",
            s.route
        ))),
        Some(false) => Err(bad(format!(
            "service_drain.route `{}` must be an `internal` route: the gateway calls it",
            s.route
        ))),
        Some(true) => Ok(()),
    }
}

fn validate_models(ms: &[Slot]) -> Result<(), NodeWorkloadRefusal> {
    let bad = |m: String| refuse("model_slot_invalid", m);
    if ms.len() > 8 {
        return Err(bad(format!("{} model slots (at most 8)", ms.len())));
    }
    for (i, m) in ms.iter().enumerate() {
        if !word_ok(&m.slot) {
            return Err(bad(format!("models[{i}]: slot name `{}`", m.slot)));
        }
        let Some(acc) = m.accepts.as_ref() else {
            return Err(bad(format!("models[{i}] ({}): `accepts` is required", m.slot)));
        };
        if acc.kind != "voice" && acc.kind != "voice-pack" {
            return Err(bad(format!("models[{i}] ({}): accepts.kind `{}`", m.slot, acc.kind)));
        }
        if acc.runtime.as_deref().is_some_and(|r| !r.is_empty() && !runtime_ok(r)) {
            return Err(bad(format!("models[{i}] ({}): accepts.runtime is not valid", m.slot)));
        }
        if refused_target(&m.target) || !target_shape_ok(&m.target) || m.target.len() > 128 {
            return Err(bad(format!("models[{i}] ({}): target `{}`", m.slot, m.target)));
        }
        let clash = ms[..i].iter().find(|o| o.slot == m.slot || overlaps(&o.target, &m.target));
        if let Some(o) = clash {
            return Err(bad(format!(
                "models[{i}] ({}): slot or target repeats or nests with {}",
                m.slot, o.slot
            )));
        }
    }
    Ok(())
}

fn validate_env(addon: &str, env: &BTreeMap<String, EnvBound>) -> Result<(), NodeWorkloadRefusal> {
    if env.len() > 32 {
        return Err(refuse("env_bound_invalid", format!("{} env keys (at most 32)", env.len())));
    }
    let prefix = env_prefix(addon);
    // BTreeMap iterates in byte order, as the agent's sorted keys do.
    for (k, b) in env {
        if let Some(p) = REFUSED_ENV_PREFIXES.iter().find(|p| k.starts_with(**p)) {
            return Err(refuse(
                "env_key_refused_prefix",
                format!("env key `{k}` starts with refused prefix {p}"),
            ));
        }
        if !env_key_ok(k) || !k.starts_with(prefix.as_str()) {
            return Err(refuse(
                "env_key_outside_prefix",
                format!("env key `{k}` must start with {prefix}"),
            ));
        }
        let bad = |m: String| refuse("env_bound_invalid", m);
        if let Some(vals) = &b.one_of {
            if b.min.is_some() || b.max.is_some() || vals.is_empty() || vals.len() > 32 {
                return Err(bad(format!("env {k}: one_of takes 1..32 values and no min or max")));
            }
            if let Some(v) = vals.iter().find(|v| !enum_val_ok(v)) {
                return Err(bad(format!("env {k}: enum value `{v}`")));
            }
            continue;
        }
        if b.min.is_none() && b.max.is_none() {
            return Err(bad(format!("env {k}: needs min and/or max, or one_of")));
        }
        if let (Some(lo), Some(hi)) = (b.min, b.max) {
            if lo > hi {
                return Err(bad(format!("env {k}: min {lo} is above max {hi}")));
            }
        }
    }
    Ok(())
}

/// `accel.slots_env` names one of the decl's own declared env keys, and that
/// key has an integer min and/or max, not an enum (`nodewl.validateSlotsEnv`).
fn validate_slots_env(
    key: &str,
    env: &BTreeMap<String, EnvBound>,
) -> Result<(), NodeWorkloadRefusal> {
    if key.is_empty() {
        return Ok(());
    }
    let Some(b) = env.get(key) else {
        return Err(refuse(
            "accel_invalid",
            format!("accel.slots_env `{key}` is not a declared env key"),
        ));
    };
    if b.one_of.is_some() || (b.min.is_none() && b.max.is_none()) {
        return Err(refuse(
            "accel_invalid",
            format!("accel.slots_env `{key}` must have an integer min/max bound"),
        ));
    }
    Ok(())
}

fn validate_scratch(ss: &[Scratch], ms: &[Slot]) -> Result<(), NodeWorkloadRefusal> {
    let bad = |m: String| refuse("scratch_invalid", m);
    if ss.len() > 4 {
        return Err(bad(format!("{} scratch entries (at most 4)", ss.len())));
    }
    for (i, s) in ss.iter().enumerate() {
        if refused_target(&s.target) {
            return Err(refuse(
                "scratch_target_refused",
                format!("scratch[{i}]: target `{}` is not writable space", s.target),
            ));
        }
        if !target_shape_ok(&s.target) || s.target.len() > 128 {
            return Err(bad(format!("scratch[{i}]: target `{}`", s.target)));
        }
        if s.max_mb.is_some() == s.tmpfs_mb.is_some() {
            return Err(bad(format!("scratch[{i}]: exactly one of max_mb and tmpfs_mb")));
        }
        if s.max_mb.is_some_and(|v| !(1..=65536).contains(&v))
            || s.tmpfs_mb.is_some_and(|v| !(1..=16384).contains(&v))
        {
            return Err(bad(format!("scratch[{i}]: size out of range")));
        }
        if s.exec
            && (s.max_mb.is_some_and(|v| v > MAX_EXEC_SCRATCH_MB)
                || s.tmpfs_mb.is_some_and(|v| v > MAX_EXEC_SCRATCH_MB))
        {
            return Err(bad(format!(
                "scratch[{i}]: an exec scratch is at most {MAX_EXEC_SCRATCH_MB} MiB"
            )));
        }
        if s.exec && ss[..i].iter().any(|o| o.exec) {
            return Err(bad(format!("scratch[{i}]: a second exec scratch")));
        }
        if ss[..i].iter().any(|o| o.target == s.target) {
            return Err(bad(format!("scratch[{i}]: target `{}` repeats", s.target)));
        }
        if let Some(m) = ms.iter().find(|m| overlaps(&m.target, &s.target)) {
            return Err(refuse(
                "scratch_in_model_slot",
                format!(
                    "scratch[{i}]: target `{}` overlaps model slot {} ({})",
                    s.target, m.slot, m.target
                ),
            ));
        }
    }
    Ok(())
}

/// The doors a validated declaration needs: one `(addon, workload)` per
/// workload, in file order. The names are already held to the door-name rules
/// (`door_name_invalid`, `door_name_too_long`) by [`parse_node_workloads`],
/// so `noo-stunnel-<addon>-<workload>` is a legal DNS label. Harness H6's
/// door-leaf issuance plugs in here; until it lands only the tests call it.
#[cfg_attr(not(test), allow(dead_code))]
pub fn node_workload_doors(addon: &str, parsed: &[NodeWorkload]) -> Vec<(String, String)> {
    parsed.iter().map(|w| (addon.to_string(), w.name.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/addons/testdata/i300/node-workloads")
    }

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(dir().join(name)).unwrap()
    }

    fn lock_images() -> BTreeMap<String, String> {
        let v: Value = serde_json::from_slice(&read("lock.json")).unwrap();
        v["images"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, r)| (k.clone(), r.as_str().unwrap().to_string()))
            .collect()
    }

    fn routes() -> BTreeMap<String, bool> {
        routes_from_json(&read("routes.json"))
    }

    fn cases() -> Vec<Value> {
        let v: Value = serde_json::from_slice(&read("cases.json")).unwrap();
        v.as_array().unwrap().clone()
    }

    #[test]
    fn every_fixture_gives_exactly_its_verdict_and_code() {
        let images = lock_images();
        let cases = cases();
        let mut valid = 0;
        let mut refused = 0;
        // Every mismatch is collected, so one run names every fixture that flipped.
        let mut mismatches: Vec<String> = Vec::new();
        for c in &cases {
            let file = c["file"].as_str().unwrap();
            let want = c["code"].as_str().unwrap();
            let addon = c.get("addon").and_then(Value::as_str).unwrap_or("rhaddon");
            let got = parse_node_workloads(addon, &read(file), &images, Some(&routes()));
            if want.is_empty() {
                valid += 1;
            } else {
                refused += 1;
            }
            let (code, empty_msg, msg) = match &got {
                Ok(_) => ("ok".to_string(), false, String::new()),
                Err(e) => (e.code().to_string(), e.message().is_empty(), e.to_string()),
            };
            let want_code = if want.is_empty() { "ok" } else { want };
            if code != want_code {
                mismatches.push(format!("{file}: expected {want_code}, got {code} {msg}"));
            } else if empty_msg {
                mismatches.push(format!("{file}: expected {want_code}, got no message"));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} fixtures differ:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
        assert!(valid >= 9 && refused >= 49, "read {valid} valid and {refused} refusals");
    }

    #[test]
    fn a_null_in_an_optional_field_is_refused_as_field_type() {
        // `min` is an Option: serde alone reads the null as None, and the decl
        // (max 4 still bounds the key) stays valid. Only the null guard refuses it.
        let images = lock_images();
        let routes = routes();
        let text = String::from_utf8(read("valid-full.json")).unwrap();
        let nulled = text.replace("\"min\": 1,", "\"min\": null,");
        assert_ne!(nulled, text);
        let ok = parse_node_workloads("rhaddon", text.as_bytes(), &images, Some(&routes));
        assert!(ok.is_ok(), "{:?}", ok.err());
        let got = parse_node_workloads("rhaddon", nulled.as_bytes(), &images, Some(&routes));
        assert_eq!(got.unwrap_err().code(), "field_type");
    }

    #[test]
    fn every_file_in_the_directory_is_a_case_and_back() {
        let listed: BTreeSet<String> =
            cases().iter().map(|c| c["file"].as_str().unwrap().to_string()).collect();
        let on_disk: BTreeSet<String> = std::fs::read_dir(dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "cases.json" && n != "lock.json" && n != "routes.json")
            .collect();
        assert_eq!(listed, on_disk);
    }

    #[test]
    fn a_repeated_key_in_a_map_field_is_refused() {
        // `env` is a map: serde alone would keep the last RHADDON_SLOTS.
        let text = String::from_utf8(read("valid-full.json")).unwrap();
        let twice = text.replace("\"RHADDON_QUANT\"", "\"RHADDON_SLOTS\"");
        assert_ne!(twice, text);
        let e = parse_node_workloads("rhaddon", twice.as_bytes(), &lock_images(), Some(&routes())).unwrap_err();
        assert_eq!(e.code(), "duplicate_key");
        assert!(e.message().contains("RHADDON_SLOTS"), "{e}");
    }

    #[test]
    fn a_repeat_is_found_before_a_type_error_and_in_a_nested_array() {
        let nested = "[[1, [\"a\"], \u{7b}\"k\": 1, \"k\": 2\u{7d}]]";
        let e = parse_node_workloads("rhaddon", nested.as_bytes(), &lock_images(), Some(&routes()));
        assert_eq!(e.unwrap_err().code(), "duplicate_key");
        // Same key at two depths is not a repeat.
        let ok = "[\u{7b}\"a\": \u{7b}\"a\": 1\u{7d}\u{7d}]";
        assert_eq!(find_duplicate_key(ok.as_bytes()), None);
        assert_eq!(find_duplicate_key(b"not json"), None);
    }

    #[test]
    fn a_null_is_field_type_and_document_order_decides_against_a_repeat() {
        let text = String::from_utf8(read("valid-full.json")).unwrap();
        let nulled = text.replace("\"gpu\": 1", "\"gpu\": null");
        assert_ne!(nulled, text);
        let e = parse_node_workloads("rhaddon", nulled.as_bytes(), &lock_images(), Some(&routes())).unwrap_err();
        assert_eq!(e.code(), "field_type");
        // Document order decides: health (a repeat) comes before accel (the null).
        let both = nulled.replace("\"live\":", "\"ready\":");
        let e = parse_node_workloads("rhaddon", both.as_bytes(), &lock_images(), Some(&routes())).unwrap_err();
        assert_eq!(e.code(), "duplicate_key");
        // And the other way: the null first, the repeat after it in env.
        let both = nulled.replace("\"RHADDON_QUANT\"", "\"RHADDON_SLOTS\"");
        let e = parse_node_workloads("rhaddon", both.as_bytes(), &lock_images(), Some(&routes())).unwrap_err();
        assert_eq!(e.code(), "field_type");
    }

    #[test]
    fn not_json_and_empty_input_are_bad_json() {
        for bytes in [&b""[..], &b"nope"[..], &b"[1, 2"[..]] {
            let e = parse_node_workloads("rhaddon", bytes, &lock_images(), Some(&routes())).unwrap_err();
            assert_eq!(e.code(), "bad_json", "{bytes:?}");
        }
    }

    #[test]
    fn the_door_seam_returns_addon_and_workload_in_file_order() {
        let bytes = read("valid-two-workloads.json");
        let got = parse_node_workloads("rhaddon", &bytes, &lock_images(), Some(&routes())).unwrap();
        let doors = node_workload_doors("rhaddon", &got);
        assert_eq!(doors.len(), got.len());
        assert!(doors.len() >= 2);
        for (door, w) in doors.iter().zip(&got) {
            assert_eq!(door.0, "rhaddon");
            assert_eq!(door.1, w.name);
        }
    }

    #[test]
    fn no_routes_skips_only_the_cross_file_half() {
        let images = lock_images();
        // Existence and internal need routes.json: without it they pass.
        for file in [
            "refuse-service-drain-route-unknown.json",
            "refuse-service-drain-route-public.json",
        ] {
            let with = parse_node_workloads("rhaddon", &read(file), &images, Some(&routes()));
            assert_eq!(with.unwrap_err().code(), "service_drain_invalid", "{file}");
            let without = parse_node_workloads("rhaddon", &read(file), &images, None);
            assert!(without.is_ok(), "{file}: {:?}", without.err());
        }
        // The shape of service_drain is checked either way.
        for file in [
            "refuse-service-drain-missing.json",
            "refuse-service-drain-route-empty.json",
            "refuse-service-drain-route-name.json",
            "refuse-service-drain-timeout-zero.json",
            "refuse-service-drain-timeout-3601.json",
        ] {
            let got = parse_node_workloads("rhaddon", &read(file), &images, None);
            assert_eq!(got.unwrap_err().code(), "service_drain_invalid", "{file}");
        }
        let f = "refuse-service-drain-unknown-field.json";
        let got = parse_node_workloads("rhaddon", &read(f), &images, None);
        assert_eq!(got.unwrap_err().code(), "unknown_field");
    }

    #[test]
    fn slots_env_naming_a_one_of_key_is_accel_invalid() {
        let images = lock_images();
        let text = String::from_utf8(read("valid-full.json")).unwrap();
        let from = "\"slots_env\": \"RHADDON_SLOTS\"";
        assert!(text.contains(from), "valid-full.json names a slots_env");
        // RHADDON_QUANT is a one_of key: no integer bound to size slots by.
        let bad = text.replace(from, "\"slots_env\": \"RHADDON_QUANT\"");
        let got = parse_node_workloads("rhaddon", bad.as_bytes(), &images, None);
        assert_eq!(got.unwrap_err().code(), "accel_invalid");
        let ok = parse_node_workloads("rhaddon", text.as_bytes(), &images, None);
        assert!(ok.is_ok(), "{:?}", ok.err());
    }

    #[test]
    fn routes_from_json_reads_name_to_internal() {
        let r = routes();
        assert_eq!(r.get("drain"), Some(&true));
        assert_eq!(r.get("status"), Some(&false));
        assert!(routes_from_json(b"nope").is_empty());
    }

    #[test]
    fn the_env_prefix_is_the_name_upper_cased() {
        assert_eq!(env_prefix("rhaddon"), "RHADDON_");
        assert_eq!(env_prefix("rh-addon"), "RH_ADDON_");
    }
}
