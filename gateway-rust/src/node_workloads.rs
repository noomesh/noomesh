// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Wired in by i300 H3/H4; until then only its tests call it.
#![allow(dead_code)]

//! The gateway's validators for the i300 contract
//! (`docs/reference/node-workloads.md`): an add-on's `node-workloads.json`
//! (`noo-addon-node-workloads/1`), a catalog model set's manifest
//! (`noo-model-set/1`) and the `node_workloads` entry of desired-config.
//!
//! This is a port of the node agent's reference validator,
//! `node-agent-go/internal/nodewl` (`decl.go`, `desired.go`, `modelset.go`,
//! `profile.go`, `errors.go`, `reasons.go`), and is held to the same fixtures
//! (`tests/fixtures/i300`, of which `src/testdata/i300` is a byte-identical copy:
//! `tests/test_i300_fixture_parity.py`). The first failing rule wins, in the Go
//! order. Every refusal carries a stable code from [`code`]; the fixtures pin
//! each.
//!
//! ## Strictness
//!
//! * A repeated object key, at any depth, is refused (`duplicate_key`) by a
//!   pass over the raw bytes BEFORE anything is deserialized: serde derive
//!   refuses a repeated struct field, but a map field and `serde_json::Value`
//!   keep the last value silently, and Go keeps the last too, so a document
//!   could otherwise be read two ways.
//! * Every struct is `deny_unknown_fields`; no struct uses `serde(flatten)`
//!   (it would switch that check off).
//! * serde errors are mapped to the contract's codes by [`classify`].
//!
//! Nothing here reads the lock, the network or a clock: the lock's image names
//! are passed in.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Every stable code a validator here returns: the file-level refusal codes
/// and the desired-config reasons. One home; the contract lists the same.
pub mod code {
    // Shared by every parser.
    pub const BAD_JSON: &str = "bad_json";
    pub const UNKNOWN_FIELD: &str = "unknown_field";
    pub const FIELD_TYPE: &str = "field_type";
    pub const FIELD_MISSING: &str = "field_missing";
    pub const BAD_FORMAT: &str = "bad_format";
    pub const DUPLICATE_KEY: &str = "duplicate_key";

    // node-workloads.json.
    pub const WORKLOADS_INVALID: &str = "workloads_invalid";
    pub const DOOR_NAME_INVALID: &str = "door_name_invalid";
    pub const DOOR_NAME_TOO_LONG: &str = "door_name_too_long";
    pub const NAME_DUPLICATE: &str = "name_duplicate";
    pub const IMAGE_NOT_IN_LOCK: &str = "image_not_in_lock";
    pub const UID_INVALID: &str = "uid_invalid";
    pub const COMMAND_INVALID: &str = "command_invalid";
    pub const PORT_INVALID: &str = "port_invalid";
    pub const PROTOCOLS_INVALID: &str = "protocols_invalid";
    pub const HEALTH_INVALID: &str = "health_invalid";
    pub const DRAIN_INVALID: &str = "drain_invalid";
    pub const ACCEL_INVALID: &str = "accel_invalid";
    pub const MODEL_SLOT_INVALID: &str = "model_slot_invalid";
    pub const ENV_KEY_OUTSIDE_PREFIX: &str = "env_key_outside_prefix";
    pub const ENV_KEY_REFUSED_PREFIX: &str = "env_key_refused_prefix";
    pub const ENV_BOUND_INVALID: &str = "env_bound_invalid";
    pub const SCRATCH_TARGET_REFUSED: &str = "scratch_target_refused";
    pub const SCRATCH_INVALID: &str = "scratch_invalid";
    pub const SCRATCH_IN_MODEL_SLOT: &str = "scratch_in_model_slot";
    pub const LIMITS_INVALID: &str = "limits_invalid";

    // model-set.json.
    pub const ID_INVALID: &str = "id_invalid";
    pub const REVISION_INVALID: &str = "revision_invalid";
    pub const KIND_INVALID: &str = "kind_invalid";
    pub const MODALITY_INVALID: &str = "modality_invalid";
    pub const RUNTIME_INVALID: &str = "runtime_invalid";
    pub const SOURCE_INVALID: &str = "source_invalid";
    pub const LICENSE_INVALID: &str = "license_invalid";
    pub const PATH_INVALID: &str = "path_invalid";
    pub const SHA256_INVALID: &str = "sha256_invalid";
    pub const FILES_INVALID: &str = "files_invalid";
    pub const NOTICE_NOT_IN_FILES: &str = "notice_not_in_files";
    pub const PROFILE_INVALID: &str = "profile_invalid";
    pub const ARCH_INVALID: &str = "arch_invalid";
    pub const FITS_REQUIRED: &str = "fits_required";
    pub const FITS_FORBIDDEN: &str = "fits_forbidden";
    pub const FITS_INVALID: &str = "fits_invalid";
    pub const TRUST_REQUIRED: &str = "trust_required";
    pub const TRUST_INVALID: &str = "trust_invalid";

    // Reasons (desired-config codes; also the placement refusal codes).
    pub const DECL_INVALID: &str = "decl_invalid";
    pub const DESIRED_INVALID: &str = "desired_invalid";
    pub const DOOR_LEAF_MISSING: &str = "door_leaf_missing";
    pub const IMAGE_MISSING: &str = "image_missing";
    pub const IMAGE_DIGEST_MISMATCH: &str = "image_digest_mismatch";
    pub const SET_MISSING: &str = "set_missing";
    pub const SET_SLOT_INVALID: &str = "set_slot_invalid";
    pub const SET_UNVERIFIED: &str = "set_unverified";
    pub const DISK: &str = "disk";
    pub const CONSENT_NONE: &str = "consent_none";
    pub const CONSENT_UNAPPROVED: &str = "consent_unapproved";
    pub const NVIDIA_RUNTIME_MISSING: &str = "nvidia_runtime_missing";
    pub const DRIVER_CAPS_MISSING: &str = "driver_caps_missing";
    pub const COMPUTE_CAP_LOW: &str = "compute_cap_low";
    pub const ARCH_MISMATCH: &str = "arch_mismatch";
    pub const CONTROLLER_HOST: &str = "controller_host";
    pub const ADMIT_INVALID: &str = "admit_invalid";
    pub const ENV_OUT_OF_BOUNDS: &str = "env_out_of_bounds";
    pub const CONTAINER_CONFLICT: &str = "container_conflict";
    pub const START_TIMEOUT: &str = "start_timeout";
    pub const CRASHED: &str = "crashed";
    pub const DRAIN_TIMEOUT: &str = "drain_timeout";

    /// The agent's reason vocabulary, in the contract's order (reasons.go).
    pub const REASONS: &[&str] = &[
        DECL_INVALID,
        DESIRED_INVALID,
        DOOR_LEAF_MISSING,
        IMAGE_MISSING,
        IMAGE_DIGEST_MISMATCH,
        SET_MISSING,
        SET_SLOT_INVALID,
        SET_UNVERIFIED,
        PROFILE_INVALID,
        DISK,
        CONSENT_NONE,
        CONSENT_UNAPPROVED,
        NVIDIA_RUNTIME_MISSING,
        DRIVER_CAPS_MISSING,
        COMPUTE_CAP_LOW,
        ARCH_MISMATCH,
        CONTROLLER_HOST,
        ADMIT_INVALID,
        ENV_OUT_OF_BOUNDS,
        CONTAINER_CONFLICT,
        START_TIMEOUT,
        CRASHED,
        DRAIN_TIMEOUT,
    ];
}

/// `format` of node-workloads.json.
pub const FORMAT_NODE_WORKLOADS: &str = "noo-addon-node-workloads/1";
/// `format` of model-set.json.
pub const FORMAT_MODEL_SET: &str = "noo-model-set/1";

/// The door's DNS SAN is `noo-stunnel-<addon>-<workload>`, one DNS label of at
/// most 63 characters: 12 for the prefix, so `len(addon)+1+len(workload)` is at
/// most 51.
pub const MAX_DOOR_NAMES: usize = 51;

const STATE_PROVISIONED: &str = "provisioned";
const STATE_RUNNING: &str = "running";
const STATE_ABSENT: &str = "absent";

const DIGESTS_AUTHENTICATED: &str = "authenticated";
const DIGESTS_OPERATOR_TRUST: &str = "operator-trusted-local";
const MAX_SET_FILES: usize = 64;
const MAX_SET_FILE_BYTES: i64 = 1 << 40;

/// These can never start a declared env key, whatever the add-on is called.
const REFUSED_ENV_PREFIXES: &[&str] = &[
    "NOO_",
    "NVIDIA_",
    "CUDA_",
    "LD_",
    "PYTHON",
    "HF_",
    "TRANSFORMERS_",
];

/// A typed refusal. `code` is stable and is what the fixtures pin; `detail`
/// is for a human and may change; `inner` is the nested code of a
/// `decl_invalid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub detail: String,
    pub inner: Option<&'static str>,
}

impl Refusal {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Refusal {
            code,
            detail: detail.into(),
            inner: None,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)?;
        if let Some(i) = self.inner {
            write!(f, "({i})")?;
        }
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        Ok(())
    }
}

impl std::error::Error for Refusal {}

fn fail<T>(code: &'static str, detail: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal::new(code, detail))
}

macro_rules! re {
    ($p:expr) => {{
        static R: LazyLock<Regex> = LazyLock::new(|| Regex::new($p).expect("static regex"));
        &*R
    }};
}

// The Go regexes, verbatim; `\S` is spelled out because Go's is ASCII-only.
fn door_name_re() -> &'static Regex {
    re!(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
}
fn word_re() -> &'static Regex {
    re!(r"^[a-z][a-z0-9-]{0,31}$")
}
fn http_path_re() -> &'static Regex {
    re!(r"^/[A-Za-z0-9._~/-]*$")
}
fn target_re() -> &'static Regex {
    re!(r"^/[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$")
}
fn runtime_re() -> &'static Regex {
    re!(r"^[a-z0-9][a-z0-9._-]{0,63}$")
}
fn env_key_re() -> &'static Regex {
    re!(r"^[A-Z][A-Z0-9_]{0,63}$")
}
fn enum_val_re() -> &'static Regex {
    re!(r"^[A-Za-z0-9._:-]{1,64}$")
}
fn set_profile_re() -> &'static Regex {
    re!(r"^[a-z][a-z0-9-]{0,31}$")
}
fn min_compute_re() -> &'static Regex {
    re!(r"^[0-9]{1,2}\.[0-9]$")
}
fn sha256_re() -> &'static Regex {
    re!(r"^[0-9a-f]{64}$")
}
fn commit_re() -> &'static Regex {
    re!(r"^[0-9a-f]{40}$")
}
fn hf_repo_re() -> &'static Regex {
    re!(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
}
fn license_id_re() -> &'static Regex {
    re!(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
}
fn https_url_re() -> &'static Regex {
    re!(r"^https://[^ \t\n\x0c\r]{1,500}$")
}
fn file_comp_re() -> &'static Regex {
    re!(r"^[A-Za-z0-9._-]+$")
}
fn digest_re() -> &'static Regex {
    re!(r"^sha256:[0-9a-f]{64}$")
}
fn uuid_re() -> &'static Regex {
    re!(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
}
fn set_id_re() -> &'static Regex {
    re!(r"^[a-z0-9][a-z0-9._-]{0,63}$")
}
fn set_rev_re() -> &'static Regex {
    re!(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
}
fn int_str_re() -> &'static Regex {
    re!(r"^-?[0-9]{1,18}$")
}
fn cn_re() -> &'static Regex {
    re!(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
}
fn compute_cap_re() -> &'static Regex {
    re!(r"^([0-9]{1,2})\.([0-9]{1,2})$")
}

// ---------------------------------------------------------------------------
// Strict decoding: duplicate keys, serde error mapping, required keys.
// ---------------------------------------------------------------------------

/// Marks the serde custom error the duplicate-key pass raises.
const DUP_MARK: &str = "\u{1}dup:";

/// A JSON value that is only walked, never kept: it exists to see every
/// object key of the raw bytes, which `serde_json::Value` would collapse.
struct Strict;

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> Result<Strict, E> {
        Ok(Strict)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Strict, E> {
        Ok(Strict)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Strict, E> {
        Ok(Strict)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Strict, E> {
        Ok(Strict)
    }
    fn visit_str<E>(self, _: &str) -> Result<Strict, E> {
        Ok(Strict)
    }
    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict)
    }
    fn visit_none<E>(self) -> Result<Strict, E> {
        Ok(Strict)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        while seq.next_element::<Strict>()?.is_some() {}
        Ok(Strict)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(k) = map.next_key::<String>()? {
            if !seen.insert(k.clone()) {
                return Err(serde::de::Error::custom(format!("{DUP_MARK}{k}")));
            }
            map.next_value::<Strict>()?;
        }
        Ok(Strict)
    }
}

/// Refuse a repeated object key, at any depth. Syntax errors are not this
/// pass's business: the typed decode that follows reports them as `bad_json`.
fn check_duplicate_keys(b: &[u8]) -> Result<(), Refusal> {
    let mut de = serde_json::Deserializer::from_slice(b);
    if let Err(e) = Strict::deserialize(&mut de) {
        let msg = e.to_string();
        if let Some(at) = msg.find(DUP_MARK) {
            let rest = &msg[at + DUP_MARK.len()..];
            // serde_json appends " at line L column C" to a custom message.
            let key = rest.rsplit_once(" at line ").map_or(rest, |(k, _)| k);
            return fail(
                code::DUPLICATE_KEY,
                format!("key {key:?} is repeated in an object"),
            );
        }
    }
    Ok(())
}

/// Where the contract allows JSON `null` ("## Nullable fields"), as pointers
/// from the document root with `*` for any array index. Everywhere else a
/// null is `field_type`: Go reads null on a plain field as its zero value and
/// this port's optional fields read it as absent, so without this walk both
/// would accept `"accel": {"gpu": null}` as something it is not.
const NULLABLE_DESIRED: &[&str] = &["/node_workloads/*/reservation"];
/// The same rule for one entry validated on its own.
const NULLABLE_ENTRY: &[&str] = &["/reservation"];
/// `node-workloads.json` and `model-set.json` allow null nowhere.
const NULLABLE_NONE: &[&str] = &[];

enum Seg<'a> {
    Key(&'a str),
    Index(usize),
}

/// Refuse a null outside `nullable`, judged on the raw document (so a
/// missing key and a null key stay apart). A document that does not parse is
/// left to the typed decode, which reports `bad_json`.
fn check_nulls(b: &[u8], nullable: &[&str]) -> Result<(), Refusal> {
    match serde_json::from_slice::<Value>(b) {
        Ok(v) => check_nulls_value(&v, nullable),
        Err(_) => Ok(()),
    }
}

fn check_nulls_value(v: &Value, nullable: &[&str]) -> Result<(), Refusal> {
    let mut path = Vec::new();
    walk_nulls(v, &mut path, nullable)
}

fn walk_nulls<'a>(v: &'a Value, path: &mut Vec<Seg<'a>>, nullable: &[&str]) -> Result<(), Refusal> {
    match v {
        Value::Null if !path.is_empty() => {
            if nullable.iter().any(|p| pointer_matches(p, path)) {
                Ok(())
            } else {
                fail(code::FIELD_TYPE, format!("{} is null, which is allowed only at {nullable:?}", render_path(path)))
            }
        }
        Value::Object(m) => {
            for (k, x) in m {
                path.push(Seg::Key(k));
                walk_nulls(x, path, nullable)?;
                path.pop();
            }
            Ok(())
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                path.push(Seg::Index(i));
                walk_nulls(x, path, nullable)?;
                path.pop();
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// `*` matches an array index only; an object key `"0"` is not an index.
fn pointer_matches(pattern: &str, path: &[Seg]) -> bool {
    let want: Vec<&str> = pattern.split('/').skip(1).collect();
    want.len() == path.len()
        && want.iter().zip(path).all(|(w, seg)| match seg {
            Seg::Key(k) => *w != "*" && w == k,
            Seg::Index(_) => *w == "*",
        })
}

fn render_path(path: &[Seg]) -> String {
    path.iter()
        .map(|s| match s {
            Seg::Key(k) => format!("/{k}"),
            Seg::Index(i) => format!("/{i}"),
        })
        .collect()
}

/// Map a serde_json error to a contract code. A syntax or EOF error is
/// `bad_json` (this includes data after the document); a data error is told
/// apart by serde's message: `unknown field`, `missing field`, anything else
/// is a value of the wrong type or range.
fn classify(e: &serde_json::Error) -> &'static str {
    if e.classify() != serde_json::error::Category::Data {
        return code::BAD_JSON;
    }
    let m = e.to_string();
    if m.starts_with("unknown field") {
        code::UNKNOWN_FIELD
    } else if m.starts_with("missing field") {
        code::FIELD_MISSING
    } else {
        code::FIELD_TYPE
    }
}

fn from_serde(e: serde_json::Error) -> Refusal {
    Refusal::new(classify(&e), e.to_string())
}

/// Decode exactly one JSON value into T: a repeated key is refused, so are
/// unknown fields and anything after the value.
fn decode_strict<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, Refusal> {
    check_duplicate_keys(b)?;
    serde_json::from_slice::<T>(b).map_err(from_serde)
}

/// Decode a value that already came out of a strict document.
fn decode_value<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, Refusal> {
    serde_json::from_value::<T>(v.clone()).map_err(from_serde)
}

/// Refuse an object that lacks one of `keys`. Anything that is not an object
/// is left to the typed decode.
fn require_keys(v: Option<&Value>, whr: &str, keys: &[&str]) -> Result<(), Refusal> {
    let Some(Value::Object(m)) = v else {
        return Ok(());
    };
    for k in keys {
        if !m.contains_key(*k) {
            return fail(code::FIELD_MISSING, format!("{whr}: `{k}` is required"));
        }
    }
    Ok(())
}

fn generic(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap_or(Value::Null)
}

fn field<'a>(v: Option<&'a Value>, k: &str) -> Option<&'a Value> {
    v.and_then(|v| v.get(k))
}

fn items<'a>(v: Option<&'a Value>, k: &str) -> &'a [Value] {
    field(v, k)
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

// ---------------------------------------------------------------------------
// noo-addon-node-workloads/1
// ---------------------------------------------------------------------------

/// One validated workload of node-workloads.json. In desired-config it
/// travels verbatim as `decl`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Decl {
    pub name: String,
    pub image: String,
    pub uid: i64,
    pub command: Option<Vec<String>>,
    pub port: i64,
    pub protocols: Vec<String>,
    pub health: Health,
    pub drain: Drain,
    pub accel: Accel,
    pub models: Vec<Slot>,
    pub env: BTreeMap<String, EnvBound>,
    pub scratch: Vec<Scratch>,
    pub limits: Limits,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Health {
    pub ready: String,
    pub live: String,
    pub start_secs: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Drain {
    pub path: String,
    pub timeout_secs: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Accel {
    pub gpu: i64,
    pub realtime: bool,
}

/// A model slot: the agent mounts the set the operator chose, read-only, at
/// `target`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Slot {
    pub slot: String,
    pub target: String,
    pub accepts: Option<Accepts>,
    pub many: bool,
    pub optional: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Accepts {
    pub kind: String,
    pub runtime: String,
}

/// Bounds one declared env key: an integer range (`min` and/or `max`) or an
/// enum (`one_of`). Values are strings in desired-config.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EnvBound {
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub one_of: Option<Vec<String>>,
}

/// Writable space: a size-capped named volume (`max_mb`) or a tmpfs
/// (`tmpfs_mb`), exactly one of the two.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Scratch {
    pub target: String,
    pub max_mb: Option<i64>,
    pub tmpfs_mb: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub ram_mb: i64,
    pub cpus: f64,
    pub pids: i64,
}

/// A validated node-workloads.json.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NodeWorkloads {
    pub format: String,
    pub workloads: Vec<Decl>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct DeclFile {
    format: String,
    workloads: Vec<Value>,
}

/// The prefix every env key of `addon` must carry: the name upper-cased, `-`
/// as `_`.
pub fn env_prefix(addon: &str) -> String {
    format!("{}_", addon.to_uppercase().replace('-', "_"))
}

/// Validate a node-workloads.json for `addon`. `lock_images` is the set of
/// image NAMES in the add-on's verified lock (`images` map keys); a
/// workload's `image` must be one of them. The first refusal wins.
pub fn validate_decl(
    bytes: &[u8],
    addon: &str,
    lock_images: &BTreeSet<String>,
) -> Result<NodeWorkloads, Refusal> {
    check_duplicate_keys(bytes)?;
    check_nulls(bytes, NULLABLE_NONE)?;
    let file: DeclFile = decode_strict(bytes)?;
    let g = generic(bytes);
    require_keys(Some(&g), "node-workloads.json", &["format", "workloads"])?;
    if file.format != FORMAT_NODE_WORKLOADS {
        return fail(
            code::BAD_FORMAT,
            format!("format is {:?}, want {:?}", file.format, FORMAT_NODE_WORKLOADS),
        );
    }
    if file.workloads.is_empty() || file.workloads.len() > 16 {
        return fail(
            code::WORKLOADS_INVALID,
            format!("{} workloads (1..16)", file.workloads.len()),
        );
    }
    let mut out = Vec::with_capacity(file.workloads.len());
    let mut seen: HashSet<String> = HashSet::new();
    for (i, raw) in file.workloads.iter().enumerate() {
        let d = parse_workload(addon, raw, Some(lock_images))?;
        if !seen.insert(d.name.clone()) {
            return fail(
                code::NAME_DUPLICATE,
                format!("workloads[{i}]: name {:?} is declared twice", d.name),
            );
        }
        out.push(d);
    }
    Ok(NodeWorkloads {
        format: file.format,
        workloads: out,
    })
}

/// Decode and validate one workload object. `lock` None skips the
/// image-name-in-lock rule: a desired-config entry carries the image by name
/// and digest, and the gateway has already held the name to the verified lock.
fn parse_workload(
    addon: &str,
    raw: &Value,
    lock: Option<&BTreeSet<String>>,
) -> Result<Decl, Refusal> {
    // Go decodes JSON null into a struct as a no-op, leaving the zero value.
    let d: Decl = if raw.is_null() {
        Decl::default()
    } else {
        decode_value(raw)?
    };
    require_keys(
        Some(raw),
        "workload",
        &[
            "name",
            "image",
            "uid",
            "port",
            "protocols",
            "health",
            "drain",
            "accel",
            "limits",
        ],
    )?;
    for (sub, keys) in [
        ("health", &["ready", "live", "start_secs"][..]),
        ("drain", &["path", "timeout_secs"][..]),
        ("accel", &["gpu"][..]),
        ("limits", &["ram_mb", "cpus", "pids"][..]),
    ] {
        require_keys(field(Some(raw), sub), sub, keys)?;
    }
    validate_decl_rules(addon, &d, lock)?;
    Ok(d)
}

fn ok_path(p: &str) -> bool {
    p.len() <= 128 && http_path_re().is_match(p)
}

fn refused_target(t: &str) -> bool {
    if t == "/" {
        return true;
    }
    ["/proc", "/sys", "/dev"]
        .iter()
        .any(|r| t == *r || t.starts_with(&format!("{r}/")))
}

fn overlaps(a: &str, b: &str) -> bool {
    a == b || a.starts_with(&format!("{b}/")) || b.starts_with(&format!("{a}/"))
}

fn validate_decl_rules(
    addon: &str,
    d: &Decl,
    lock: Option<&BTreeSet<String>>,
) -> Result<(), Refusal> {
    if !door_name_re().is_match(addon) {
        return fail(
            code::DOOR_NAME_INVALID,
            format!("add-on name {addon:?} must match {}", door_name_re()),
        );
    }
    if !door_name_re().is_match(&d.name) {
        return fail(
            code::DOOR_NAME_INVALID,
            format!("workload name {:?} must match {}", d.name, door_name_re()),
        );
    }
    let n = addon.len() + 1 + d.name.len();
    if n > MAX_DOOR_NAMES {
        return fail(
            code::DOOR_NAME_TOO_LONG,
            format!(
                "{addon}/{}: len(addon)+1+len(workload) is {n}, at most {MAX_DOOR_NAMES}",
                d.name
            ),
        );
    }
    match lock {
        Some(images) => {
            if !images.contains(&d.image) || !word_re().is_match(&d.image) {
                return fail(
                    code::IMAGE_NOT_IN_LOCK,
                    format!("image {:?} is not a name in the lock's images map", d.image),
                );
            }
        }
        None => {
            if !word_re().is_match(&d.image) {
                return fail(
                    code::IMAGE_NOT_IN_LOCK,
                    format!("image {:?} is not an image name", d.image),
                );
            }
        }
    }
    if d.uid < 1 || d.uid > 4_294_967_294 {
        return fail(
            code::UID_INVALID,
            format!("uid {} (1..4294967294; 0 is refused)", d.uid),
        );
    }
    if let Some(cmd) = &d.command {
        if cmd.is_empty() || cmd.len() > 16 {
            return fail(
                code::COMMAND_INVALID,
                format!("command has {} elements (1..16)", cmd.len()),
            );
        }
        for c in cmd {
            if c.is_empty() || c.len() > 256 {
                return fail(
                    code::COMMAND_INVALID,
                    "a command element is empty or over 256 bytes",
                );
            }
        }
    }
    if d.port < 1024 || d.port > 65535 {
        return fail(code::PORT_INVALID, format!("port {} (1024..65535)", d.port));
    }
    if d.protocols.is_empty() || d.protocols.len() > 2 {
        return fail(
            code::PROTOCOLS_INVALID,
            format!("{} protocols", d.protocols.len()),
        );
    }
    for p in &d.protocols {
        if p != "http" && p != "ws" {
            return fail(
                code::PROTOCOLS_INVALID,
                format!("protocol {p:?} (http, ws)"),
            );
        }
    }
    if !ok_path(&d.health.ready)
        || !ok_path(&d.health.live)
        || d.health.start_secs < 1
        || d.health.start_secs > 600
    {
        return fail(
            code::HEALTH_INVALID,
            "health needs absolute paths and start_secs 1..600",
        );
    }
    if !ok_path(&d.drain.path) || d.drain.timeout_secs < 1 || d.drain.timeout_secs > 3600 {
        return fail(
            code::DRAIN_INVALID,
            "drain needs an absolute path and timeout_secs 1..3600",
        );
    }
    if d.accel.gpu < 0 || d.accel.gpu > 8 {
        return fail(code::ACCEL_INVALID, format!("accel.gpu {} (0..8)", d.accel.gpu));
    }
    validate_models(&d.models)?;
    validate_env(addon, &d.env)?;
    validate_scratch(&d.scratch, &d.models)?;
    let l = &d.limits;
    if l.ram_mb < 64
        || l.ram_mb > 1_048_576
        || l.cpus < 0.1
        || l.cpus > 128.0
        || l.pids < 1
        || l.pids > 32768
    {
        return fail(
            code::LIMITS_INVALID,
            "limits out of range: ram_mb 64..1048576, cpus 0.1..128, pids 1..32768",
        );
    }
    Ok(())
}

fn validate_models(ms: &[Slot]) -> Result<(), Refusal> {
    if ms.len() > 8 {
        return fail(
            code::MODEL_SLOT_INVALID,
            format!("{} model slots (at most 8)", ms.len()),
        );
    }
    for (i, m) in ms.iter().enumerate() {
        if !word_re().is_match(&m.slot) {
            return fail(
                code::MODEL_SLOT_INVALID,
                format!("models[{i}]: slot name {:?}", m.slot),
            );
        }
        let Some(acc) = &m.accepts else {
            return fail(
                code::MODEL_SLOT_INVALID,
                format!("models[{i}] ({}): `accepts` is required", m.slot),
            );
        };
        if acc.kind != "voice" && acc.kind != "voice-pack" {
            return fail(
                code::MODEL_SLOT_INVALID,
                format!("models[{i}] ({}): accepts.kind {:?}", m.slot, acc.kind),
            );
        }
        if !acc.runtime.is_empty() && !runtime_re().is_match(&acc.runtime) {
            return fail(
                code::MODEL_SLOT_INVALID,
                format!("models[{i}] ({}): accepts.runtime {:?}", m.slot, acc.runtime),
            );
        }
        if refused_target(&m.target) || !target_re().is_match(&m.target) || m.target.len() > 128 {
            return fail(
                code::MODEL_SLOT_INVALID,
                format!("models[{i}] ({}): target {:?}", m.slot, m.target),
            );
        }
        for o in &ms[..i] {
            if o.slot == m.slot || overlaps(&o.target, &m.target) {
                return fail(
                    code::MODEL_SLOT_INVALID,
                    format!(
                        "models[{i}] ({}): slot or target repeats or nests with {}",
                        m.slot, o.slot
                    ),
                );
            }
        }
    }
    Ok(())
}

fn validate_env(addon: &str, env: &BTreeMap<String, EnvBound>) -> Result<(), Refusal> {
    if env.len() > 32 {
        return fail(
            code::ENV_BOUND_INVALID,
            format!("{} env keys (at most 32)", env.len()),
        );
    }
    let prefix = env_prefix(addon);
    // A BTreeMap iterates in sorted key order, as the Go side sorts.
    for (k, b) in env {
        for p in REFUSED_ENV_PREFIXES {
            if k.starts_with(p) {
                return fail(
                    code::ENV_KEY_REFUSED_PREFIX,
                    format!("env key {k:?} starts with refused prefix {p}"),
                );
            }
        }
        if !env_key_re().is_match(k) || !k.starts_with(&prefix) {
            return fail(
                code::ENV_KEY_OUTSIDE_PREFIX,
                format!("env key {k:?} must start with {prefix}"),
            );
        }
        if let Some(one_of) = &b.one_of {
            if b.min.is_some() || b.max.is_some() || one_of.is_empty() || one_of.len() > 32 {
                return fail(
                    code::ENV_BOUND_INVALID,
                    format!("env {k}: one_of takes 1..32 values and no min or max"),
                );
            }
            for v in one_of {
                if !enum_val_re().is_match(v) {
                    return fail(
                        code::ENV_BOUND_INVALID,
                        format!("env {k}: enum value {v:?}"),
                    );
                }
            }
            continue;
        }
        if b.min.is_none() && b.max.is_none() {
            return fail(
                code::ENV_BOUND_INVALID,
                format!("env {k}: needs min and/or max, or one_of"),
            );
        }
        if let (Some(lo), Some(hi)) = (b.min, b.max) {
            if lo > hi {
                return fail(
                    code::ENV_BOUND_INVALID,
                    format!("env {k}: min {lo} is above max {hi}"),
                );
            }
        }
    }
    Ok(())
}

fn validate_scratch(ss: &[Scratch], ms: &[Slot]) -> Result<(), Refusal> {
    if ss.len() > 4 {
        return fail(
            code::SCRATCH_INVALID,
            format!("{} scratch entries (at most 4)", ss.len()),
        );
    }
    for (i, s) in ss.iter().enumerate() {
        if refused_target(&s.target) {
            return fail(
                code::SCRATCH_TARGET_REFUSED,
                format!("scratch[{i}]: target {:?} is not writable space", s.target),
            );
        }
        if !target_re().is_match(&s.target) || s.target.len() > 128 {
            return fail(
                code::SCRATCH_INVALID,
                format!("scratch[{i}]: target {:?}", s.target),
            );
        }
        if s.max_mb.is_none() == s.tmpfs_mb.is_none() {
            return fail(
                code::SCRATCH_INVALID,
                format!("scratch[{i}]: exactly one of max_mb and tmpfs_mb"),
            );
        }
        let bad_max = s.max_mb.is_some_and(|v| !(1..=65536).contains(&v));
        let bad_tmpfs = s.tmpfs_mb.is_some_and(|v| !(1..=16384).contains(&v));
        if bad_max || bad_tmpfs {
            return fail(
                code::SCRATCH_INVALID,
                format!("scratch[{i}]: size out of range"),
            );
        }
        for o in &ss[..i] {
            if o.target == s.target {
                return fail(
                    code::SCRATCH_INVALID,
                    format!("scratch[{i}]: target {:?} repeats", s.target),
                );
            }
        }
        for m in ms {
            if overlaps(&m.target, &s.target) {
                return fail(
                    code::SCRATCH_IN_MODEL_SLOT,
                    format!(
                        "scratch[{i}]: target {:?} overlaps model slot {} ({})",
                        s.target, m.slot, m.target
                    ),
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// noo-model-set/1
// ---------------------------------------------------------------------------

/// A validated model-set.json. The signature is a separate detached file and
/// is checked before this parse runs, over the exact bytes.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ModelSet {
    pub format: String,
    pub id: String,
    pub revision: String,
    pub kind: String,
    pub modality: String,
    pub runtime: Vec<String>,
    pub source: Source,
    pub license: License,
    pub files: Vec<SetFile>,
    pub needs: Needs,
    pub fits: Option<Fits>,
    pub trust: Option<Trust>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Source {
    pub hf: Option<HfSource>,
    pub local: Option<LocalSource>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HfSource {
    pub repo: String,
    pub r#ref: String,
    pub digests: String,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LocalSource {
    pub verified: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct License {
    pub id: String,
    pub url: String,
    pub accept: String,
    pub accepted: Option<Accepted>,
    pub notice_files: Vec<String>,
    pub additional: Vec<Additional>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Accepted {
    pub by: String,
    pub at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Additional {
    pub id: String,
    pub url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SetFile {
    pub path: String,
    pub bytes: i64,
    pub sha256: String,
    pub role: String,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Needs {
    pub profiles: Vec<SetProfile>,
    pub cpu_fallback: bool,
    pub arch: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SetProfile {
    pub name: String,
    pub accel: String,
    pub min_compute: String,
    pub vram_mb: Option<i64>,
    pub ram_mb: Option<i64>,
    pub per_slot_vram_mb: Option<i64>,
    pub realtime: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Fits {
    pub model: String,
    pub revision: String,
    pub runtime: String,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Trust {
    pub by: String,
    pub at: String,
    pub reason: String,
}

/// The file path rule of a model set: relative, no `.` or `..` component, at
/// most one directory level, charset `[A-Za-z0-9._-]`. The rail's path check
/// and the node's mount check share it.
pub fn valid_set_path(p: &str) -> bool {
    if p.is_empty() || p.len() > 129 {
        return false;
    }
    let comps: Vec<&str> = p.split('/').collect();
    if comps.len() > 2 {
        return false;
    }
    comps
        .iter()
        .all(|c| !c.is_empty() && *c != "." && *c != ".." && file_comp_re().is_match(c))
}

/// Validate a model-set.json (after its signature has been verified over
/// these exact bytes). The first refusal wins.
pub fn validate_model_set(bytes: &[u8]) -> Result<ModelSet, Refusal> {
    check_duplicate_keys(bytes)?;
    check_nulls(bytes, NULLABLE_NONE)?;
    let m: ModelSet = decode_strict(bytes)?;
    let g = generic(bytes);
    require_keys(
        Some(&g),
        "model-set.json",
        &[
            "format", "id", "revision", "kind", "modality", "runtime", "source", "license",
            "files", "needs",
        ],
    )?;
    for (sub, keys) in [
        ("license", &["id", "url", "accept"][..]),
        ("needs", &["profiles", "cpu_fallback", "arch"][..]),
    ] {
        require_keys(field(Some(&g), sub), sub, keys)?;
    }
    let src = field(Some(&g), "source");
    require_keys(field(src, "hf"), "source.hf", &["repo", "ref", "digests"])?;
    require_keys(field(src, "local"), "source.local", &["verified"])?;
    for f in items(Some(&g), "files") {
        require_keys(Some(f), "files[]", &["path", "bytes", "sha256"])?;
    }
    for p in items(field(Some(&g), "needs"), "profiles") {
        require_keys(Some(p), "needs.profiles[]", &["name", "accel"])?;
    }
    check_set(&m)?;
    Ok(m)
}

fn check_set(m: &ModelSet) -> Result<(), Refusal> {
    if m.format != FORMAT_MODEL_SET {
        return fail(
            code::BAD_FORMAT,
            format!("format is {:?}, want {:?}", m.format, FORMAT_MODEL_SET),
        );
    }
    if !set_id_re().is_match(&m.id) {
        return fail(code::ID_INVALID, format!("id {:?}", m.id));
    }
    if !set_rev_re().is_match(&m.revision) {
        return fail(code::REVISION_INVALID, format!("revision {:?}", m.revision));
    }
    if m.kind != "voice" && m.kind != "voice-pack" {
        return fail(code::KIND_INVALID, format!("kind {:?}", m.kind));
    }
    if !["speech-to-speech", "stt", "tts"].contains(&m.modality.as_str()) {
        return fail(code::MODALITY_INVALID, format!("modality {:?}", m.modality));
    }
    if m.runtime.is_empty() || m.runtime.len() > 8 {
        return fail(
            code::RUNTIME_INVALID,
            format!("{} runtime strings (1..8)", m.runtime.len()),
        );
    }
    for r in &m.runtime {
        if !runtime_re().is_match(r) {
            return fail(code::RUNTIME_INVALID, format!("runtime {r:?}"));
        }
    }
    check_source(&m.source)?;
    check_license(&m.license)?;
    check_files(&m.files, &m.license.notice_files)?;
    check_needs(&m.needs)?;
    check_fits(m)?;
    check_trust(m)
}

fn check_source(s: &Source) -> Result<(), Refusal> {
    if s.hf.is_none() == s.local.is_none() {
        return fail(code::SOURCE_INVALID, "source takes exactly one of hf and local");
    }
    if let Some(hf) = &s.hf {
        if !hf_repo_re().is_match(&hf.repo) || !commit_re().is_match(&hf.r#ref) {
            return fail(
                code::SOURCE_INVALID,
                "source.hf needs repo <org>/<name> and a 40-hex commit ref",
            );
        }
        if hf.digests != DIGESTS_AUTHENTICATED && hf.digests != DIGESTS_OPERATOR_TRUST {
            return fail(
                code::SOURCE_INVALID,
                format!("source.hf.digests {:?}", hf.digests),
            );
        }
    }
    Ok(())
}

/// Go's `time.Parse(time.RFC3339, s)`: an upper-case `T` and a `Z` or numeric
/// offset. chrono is more lenient about the separator and the case of `Z`, so
/// those two are pinned here.
fn rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() > 10
        && b[10] == b'T'
        && !s.ends_with('z')
        && chrono::DateTime::parse_from_rfc3339(s).is_ok()
}

fn check_license(l: &License) -> Result<(), Refusal> {
    if !license_id_re().is_match(&l.id) || !https_url_re().is_match(&l.url) {
        return fail(code::LICENSE_INVALID, "license id or url");
    }
    if l.accept != "none" && l.accept != "operator" {
        return fail(code::LICENSE_INVALID, format!("license.accept {:?}", l.accept));
    }
    if let Some(a) = &l.accepted {
        if l.accept == "none" || a.by.is_empty() || a.by.len() > 128 || !rfc3339(&a.at) {
            return fail(
                code::LICENSE_INVALID,
                "license.accepted needs accept=operator, by and an RFC 3339 at",
            );
        }
    }
    if l.additional.len() > 8 {
        return fail(
            code::LICENSE_INVALID,
            format!("{} additional licenses (at most 8)", l.additional.len()),
        );
    }
    for a in &l.additional {
        if !license_id_re().is_match(&a.id) || !https_url_re().is_match(&a.url) {
            return fail(code::LICENSE_INVALID, "license.additional id or url");
        }
    }
    Ok(())
}

fn check_files(files: &[SetFile], notices: &[String]) -> Result<(), Refusal> {
    if files.is_empty() || files.len() > MAX_SET_FILES {
        return fail(
            code::FILES_INVALID,
            format!("{} files (1..{MAX_SET_FILES})", files.len()),
        );
    }
    let mut have: HashSet<&str> = HashSet::new();
    for f in files {
        if !valid_set_path(&f.path) {
            return fail(code::PATH_INVALID, format!("file path {:?}", f.path));
        }
        if !sha256_re().is_match(&f.sha256) {
            return fail(
                code::SHA256_INVALID,
                format!("{}: sha256 is not 64 lower-case hex", f.path),
            );
        }
        if f.bytes < 1 || f.bytes > MAX_SET_FILE_BYTES {
            return fail(
                code::FILES_INVALID,
                format!("{}: bytes {}", f.path, f.bytes),
            );
        }
        if !["", "weights", "notice", "config"].contains(&f.role.as_str()) {
            return fail(code::FILES_INVALID, format!("{}: role {:?}", f.path, f.role));
        }
        if !have.insert(f.path.as_str()) {
            return fail(code::FILES_INVALID, format!("path {:?} is listed twice", f.path));
        }
    }
    if notices.len() > 16 {
        return fail(
            code::LICENSE_INVALID,
            format!("{} notice files (at most 16)", notices.len()),
        );
    }
    for n in notices {
        if !valid_set_path(n) {
            return fail(code::PATH_INVALID, format!("notice path {n:?}"));
        }
        if !have.contains(n.as_str()) {
            return fail(
                code::NOTICE_NOT_IN_FILES,
                format!("license.notice_files names {n:?}, which is not in files"),
            );
        }
    }
    Ok(())
}

fn check_needs(n: &Needs) -> Result<(), Refusal> {
    if n.profiles.is_empty() || n.profiles.len() > 8 {
        return fail(
            code::PROFILE_INVALID,
            format!("{} profiles (1..8)", n.profiles.len()),
        );
    }
    for p in &n.profiles {
        if !set_profile_re().is_match(&p.name) || (p.accel != "cuda" && p.accel != "cpu") {
            return fail(
                code::PROFILE_INVALID,
                format!("profile {:?}: name or accel", p.name),
            );
        }
        if !p.min_compute.is_empty() && !min_compute_re().is_match(&p.min_compute) {
            return fail(
                code::PROFILE_INVALID,
                format!("profile {:?}: min_compute {:?}", p.name, p.min_compute),
            );
        }
        for v in [p.vram_mb, p.ram_mb, p.per_slot_vram_mb].into_iter().flatten() {
            if !(1..=4_194_304).contains(&v) {
                return fail(
                    code::PROFILE_INVALID,
                    format!("profile {:?}: a size is out of range", p.name),
                );
            }
        }
    }
    if n.arch.is_empty() || n.arch.len() > 4 {
        return fail(
            code::ARCH_INVALID,
            format!("{} arch entries (1..4)", n.arch.len()),
        );
    }
    for a in &n.arch {
        if a != "amd64" && a != "arm64" {
            return fail(code::ARCH_INVALID, format!("arch {a:?}"));
        }
    }
    Ok(())
}

fn check_fits(m: &ModelSet) -> Result<(), Refusal> {
    if m.kind == "voice-pack" && m.fits.is_none() {
        return fail(code::FITS_REQUIRED, "a voice-pack states what it fits");
    }
    if m.kind != "voice-pack" && m.fits.is_some() {
        return fail(code::FITS_FORBIDDEN, "fits is for voice-pack only");
    }
    let Some(f) = &m.fits else {
        return Ok(());
    };
    let by_model = !f.model.is_empty();
    let by_runtime = !f.runtime.is_empty();
    if by_model == by_runtime || (by_runtime && !f.revision.is_empty()) {
        return fail(code::FITS_INVALID, "fits is {model[, revision]} or {runtime}");
    }
    if by_model
        && (!set_id_re().is_match(&f.model)
            || (!f.revision.is_empty() && !set_rev_re().is_match(&f.revision)))
    {
        return fail(code::FITS_INVALID, "fits.model or fits.revision is malformed");
    }
    if by_runtime && !runtime_re().is_match(&f.runtime) {
        return fail(code::FITS_INVALID, "fits.runtime is malformed");
    }
    Ok(())
}

fn check_trust(m: &ModelSet) -> Result<(), Refusal> {
    let needs = m
        .source
        .hf
        .as_ref()
        .is_some_and(|h| h.digests == DIGESTS_OPERATOR_TRUST)
        || m.source.local.as_ref().is_some_and(|l| !l.verified);
    if needs && m.trust.is_none() {
        return fail(
            code::TRUST_REQUIRED,
            "digests were not authenticated upstream: trust {by, at, reason} is required",
        );
    }
    if let Some(t) = &m.trust {
        if t.by.is_empty()
            || t.by.len() > 128
            || t.reason.is_empty()
            || t.reason.len() > 500
            || !rfc3339(&t.at)
        {
            return fail(
                code::TRUST_INVALID,
                "trust needs by, an RFC 3339 at and a reason",
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// desired-config `node_workloads`
// ---------------------------------------------------------------------------

/// One `node_workloads` row of desired-config.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DesiredEntry {
    pub addon: String,
    pub name: String,
    /// The workload object exactly as the entry carried it.
    pub decl: Value,
    /// `decl`, validated. Not part of the wire format.
    #[serde(skip)]
    pub decl_parsed: Decl,
    pub image: ImageRef,
    pub sets: BTreeMap<String, Vec<SetRef>>,
    pub env: BTreeMap<String, String>,
    pub door: Option<Door>,
    pub start_secs: i64,
    pub drain: Drain,
    /// The load profile of the main slot's set (`needs.profiles`). The shape
    /// is checked here; [`check_profile`] judges it against the set.
    pub profile: Option<String>,
    pub reservation: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ImageRef {
    pub name: String,
    /// The lock digest: the REGISTRY MANIFEST digest. Record-only on the node.
    pub digest: String,
    /// The image ID (config digest) the CLI recorded after its digest-verified
    /// pull (the `.imageid` sidecar). The node runs the worker by this ID only.
    pub id: String,
    /// The rail artifact: `noo-addon-wl_<addon>_<image>_<digest hex>_<arch>.tar`.
    pub artifact: String,
}

/// Is `artifact` the rail tar name for (addon, image name, digest)? The arch
/// is checked against the node's at runtime (F5, `arch_mismatch`).
pub fn artifact_ok(artifact: &str, addon: &str, name: &str, digest: &str) -> bool {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    let Some(arch) = artifact
        .strip_prefix(&format!("noo-addon-wl_{addon}_{name}_{hex}_"))
        .and_then(|rest| rest.strip_suffix(".tar"))
    else {
        return false;
    };
    matches!(arch, "amd64" | "arm64")
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SetRef {
    pub id: String,
    pub revision: String,
}

/// The sidecar's identity: the per-node service leaf the CLI issued
/// (`svc-addon-<addon>-<workload>`) and the client CNs it admits, which must
/// be exactly this node's agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Door {
    pub leaf: String,
    pub admit: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct DesiredFragment {
    node_workloads: Vec<Value>,
}

/// A parse-level failure inside an entry is the entry's `desired_invalid`;
/// every other code (including `duplicate_key`) is returned as itself.
fn desired_invalid(r: Refusal) -> Refusal {
    match r.code {
        code::BAD_JSON | code::UNKNOWN_FIELD | code::FIELD_TYPE | code::FIELD_MISSING => {
            Refusal::new(code::DESIRED_INVALID, r.to_string())
        }
        _ => r,
    }
}

/// Validate the `node_workloads` fragment of desired-config
/// (`{"node_workloads": [...]}`) for the node whose agent client certificate
/// has CN `agent_cn`. A refusal's code is one of the reasons in [`code`]. The
/// first refusal wins.
pub fn validate_desired(bytes: &[u8], agent_cn: &str) -> Result<Vec<DesiredEntry>, Refusal> {
    // The whole fragment is walked first: a null (even on a decl field inside
    // an entry) is `field_type` itself, never folded into desired_invalid or
    // decl_invalid.
    check_duplicate_keys(bytes)?;
    check_nulls(bytes, NULLABLE_DESIRED)?;
    let frag: DesiredFragment = decode_strict(bytes).map_err(desired_invalid)?;
    require_keys(Some(&generic(bytes)), "desired-config", &["node_workloads"])
        .map_err(desired_invalid)?;
    let mut out = Vec::with_capacity(frag.node_workloads.len());
    let mut seen: HashSet<String> = HashSet::new();
    for raw in &frag.node_workloads {
        let e = validate_desired_entry(raw, agent_cn)?;
        let k = format!("{}/{}", e.addon, e.name);
        if !seen.insert(k.clone()) {
            return fail(code::DESIRED_INVALID, format!("{k} is listed twice"));
        }
        out.push(e);
    }
    Ok(out)
}

/// Validate one `node_workloads` entry. `raw` must come from a document
/// already read strictly (no repeated keys), as [`validate_desired`] does.
pub fn validate_desired_entry(raw: &Value, agent_cn: &str) -> Result<DesiredEntry, Refusal> {
    check_nulls_value(raw, NULLABLE_ENTRY)?;
    let mut e: DesiredEntry = decode_value(raw).map_err(desired_invalid)?;
    require_keys(
        Some(raw),
        "node_workloads[]",
        &[
            "addon",
            "name",
            "decl",
            "image",
            "sets",
            "env",
            "start_secs",
            "drain",
            "reservation",
            "state",
        ],
    )
    .map_err(desired_invalid)?;
    if ![STATE_PROVISIONED, STATE_RUNNING, STATE_ABSENT].contains(&e.state.as_str()) {
        return fail(code::DESIRED_INVALID, format!("state {:?}", e.state));
    }
    if let Some(p) = &e.profile {
        if !set_profile_re().is_match(p) {
            return fail(
                code::DESIRED_INVALID,
                "profile must be a non-empty lower-case word",
            );
        }
    }
    if let Some(r) = &e.reservation {
        if !uuid_re().is_match(r) {
            return fail(
                code::DESIRED_INVALID,
                "reservation is not a canonical lower-case UUID",
            );
        }
    }
    let d = parse_workload(&e.addon, &e.decl, None).map_err(|inner| Refusal {
        code: code::DECL_INVALID,
        detail: inner.detail,
        inner: Some(inner.code),
    })?;
    e.decl_parsed = d;
    let d = &e.decl_parsed;
    if e.name != d.name {
        return fail(
            code::DESIRED_INVALID,
            format!("name {:?} differs from decl.name {:?}", e.name, d.name),
        );
    }
    if e.image.name != d.image || !digest_re().is_match(&e.image.digest) {
        return fail(
            code::IMAGE_MISSING,
            format!("image must be {{name: {:?}, digest: sha256:<64 hex>, id, artifact}}", d.image),
        );
    }
    if !digest_re().is_match(&e.image.id) {
        return fail(code::IMAGE_MISSING, "image.id must be sha256:<64 lower-case hex>");
    }
    if !artifact_ok(&e.image.artifact, &e.addon, &e.image.name, &e.image.digest) {
        return fail(
            code::IMAGE_MISSING,
            format!(
                "image.artifact must be noo-addon-wl_{}_{}_<hex of digest>_<amd64|arm64>.tar",
                e.addon, e.image.name
            ),
        );
    }
    let Some(door) = e.door.as_ref().filter(|d| !d.leaf.is_empty()) else {
        return fail(code::DOOR_LEAF_MISSING, "door.leaf is required");
    };
    let want = format!("svc-addon-{}-{}", e.addon, e.name);
    if door.leaf != want {
        return fail(
            code::DESIRED_INVALID,
            format!("door.leaf {:?}, want {want:?}", door.leaf),
        );
    }
    if door.admit.len() != 1 || door.admit[0] != agent_cn || !cn_re().is_match(agent_cn) {
        return fail(
            code::ADMIT_INVALID,
            format!("door.admit must be exactly [{agent_cn:?}]"),
        );
    }
    if e.start_secs != d.health.start_secs || e.drain != d.drain {
        return fail(
            code::DESIRED_INVALID,
            "start_secs and drain must equal the decl's",
        );
    }
    if e.state != STATE_ABSENT {
        check_sets(&e.sets, &d.models)?;
    }
    check_env_values(&e.env, &d.env)?;
    Ok(e)
}

fn check_sets(sets: &BTreeMap<String, Vec<SetRef>>, slots: &[Slot]) -> Result<(), Refusal> {
    // BTreeMap order is the sorted order the Go side iterates in.
    for (k, refs) in sets {
        let Some(s) = slots.iter().find(|s| &s.slot == k) else {
            return fail(
                code::SET_SLOT_INVALID,
                format!("sets names slot {k:?}, which the decl does not declare"),
            );
        };
        if refs.len() > 1 && !s.many {
            return fail(
                code::SET_SLOT_INVALID,
                format!("slot {k:?} takes one set (many is false)"),
            );
        }
        for r in refs {
            if !set_id_re().is_match(&r.id) || !set_rev_re().is_match(&r.revision) {
                return fail(
                    code::SET_SLOT_INVALID,
                    format!("slot {k:?}: set id or revision is malformed"),
                );
            }
        }
    }
    for s in slots {
        if !s.optional && !sets.get(&s.slot).is_some_and(|v| !v.is_empty()) {
            return fail(code::SET_MISSING, format!("slot {:?} has no set", s.slot));
        }
    }
    Ok(())
}

/// Re-check every env value against the decl's bound for its key. A key the
/// decl does not declare is out of bounds.
fn check_env_values(
    env: &BTreeMap<String, String>,
    bounds: &BTreeMap<String, EnvBound>,
) -> Result<(), Refusal> {
    for (k, v) in env {
        let Some(b) = bounds.get(k) else {
            return fail(code::ENV_OUT_OF_BOUNDS, format!("env {k} is not declared"));
        };
        if v.len() > 256 {
            return fail(code::ENV_OUT_OF_BOUNDS, format!("env {k} is over 256 bytes"));
        }
        if let Some(one_of) = &b.one_of {
            if !one_of.iter().any(|m| m == v) {
                return fail(
                    code::ENV_OUT_OF_BOUNDS,
                    format!("env {k}={v:?} is not one of the declared values"),
                );
            }
            continue;
        }
        let n = match v.parse::<i64>() {
            Ok(n) if int_str_re().is_match(v) => n,
            _ => {
                return fail(
                    code::ENV_OUT_OF_BOUNDS,
                    format!("env {k}={v:?} is not a base-10 integer"),
                )
            }
        };
        if b.min.is_some_and(|lo| n < lo) || b.max.is_some_and(|hi| n > hi) {
            return fail(
                code::ENV_OUT_OF_BOUNDS,
                format!("env {k}={n} is outside its bounds"),
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// profile.go
// ---------------------------------------------------------------------------

fn parse_compute_cap(s: &str) -> Option<(u32, u32)> {
    let c = compute_cap_re().captures(s)?;
    Some((c[1].parse().ok()?, c[2].parse().ok()?))
}

/// Whether CUDA compute capability `have` is at least `need`. The two are
/// compared as numbers, (major, minor), never as strings: `"10.0"` is above
/// `"8.0"` and `"8.10"` is above `"8.9"`. A value that does not parse is
/// `None`, which the caller treats as UNKNOWN, never as low (the i495 rule: an
/// error must not become a fact).
pub fn compute_cap_at_least(have: &str, need: &str) -> Option<bool> {
    let (h_maj, h_min) = parse_compute_cap(have)?;
    let (n_maj, n_min) = parse_compute_cap(need)?;
    Some(if h_maj != n_maj {
        h_maj > n_maj
    } else {
        h_min >= n_min
    })
}

/// Judge an entry's `profile` against the manifest of the set in its main slot
/// (the first declared model slot), which [`validate_desired`] cannot see. It
/// refuses, with `profile_invalid`, a profile that is missing, that the set
/// does not list, or that cannot serve live audio (`realtime: false`) when the
/// decl asks for a realtime workload. An absent `realtime` means a
/// realtime-capable profile.
pub fn check_profile(e: &DesiredEntry, main_set: &ModelSet) -> Result<(), Refusal> {
    let want = match e.profile.as_deref() {
        Some(p) if !p.is_empty() => p,
        _ => {
            return fail(
                code::PROFILE_INVALID,
                format!(
                    "set {} lists profiles, so the entry must name one",
                    main_set.id
                ),
            )
        }
    };
    for p in &main_set.needs.profiles {
        if p.name != want {
            continue;
        }
        if e.decl_parsed.accel.realtime && p.realtime == Some(false) {
            return fail(
                code::PROFILE_INVALID,
                format!(
                    "profile {:?} of {} cannot serve live audio and the workload is realtime",
                    p.name, main_set.id
                ),
            );
        }
        return Ok(());
    }
    fail(
        code::PROFILE_INVALID,
        format!("set {} has no profile {want:?}", main_set.id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // The fixtures are a byte-identical copy of tests/fixtures/i300 (the parity
    // test tests/test_i300_fixture_parity.py holds them equal); the agent and
    // the CLI read the same files.
    const TEST_AGENT_CN: &str = "node-a";
    const TEST_ADDON: &str = "rhaddon";

    #[derive(Deserialize)]
    struct Case {
        file: String,
        valid: bool,
        code: String,
        #[serde(default)]
        addon: Option<String>,
        #[serde(default)]
        set: Option<String>,
    }

    fn root() -> PathBuf {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/testdata/i300"))
    }

    fn read(parts: &[&str]) -> Vec<u8> {
        let mut p = root();
        for x in parts {
            p.push(x);
        }
        std::fs::read(&p).unwrap_or_else(|e| panic!("read fixture {}: {e}", p.display()))
    }

    /// The rows of `<dir>/cases.json`, after the same bookkeeping checks the
    /// Go test makes: a parse that finds nothing fails, valid agrees with an
    /// empty code, and every fixture file in the directory has a row.
    fn load_cases(dir: &str) -> Vec<Case> {
        let cases: Vec<Case> = serde_json::from_slice(&read(&[dir, "cases.json"]))
            .unwrap_or_else(|e| panic!("{dir}/cases.json: {e}"));
        assert!(!cases.is_empty(), "{dir}/cases.json has no cases");
        let mut listed: HashSet<String> = ["cases.json", "lock.json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        for c in &cases {
            listed.insert(c.file.clone());
            assert_eq!(
                c.valid,
                c.code.is_empty(),
                "{dir}/{}: valid={} with code {:?}",
                c.file,
                c.valid,
                c.code
            );
        }
        for ent in std::fs::read_dir(root().join(dir)).expect("read fixture dir") {
            let name = ent.expect("dir entry").file_name().to_string_lossy().to_string();
            assert!(listed.contains(&name), "{dir}/{name} is not in cases.json");
        }
        cases
    }

    fn check(c: &Case, r: Result<(), Refusal>) {
        if c.valid {
            assert!(r.is_ok(), "{}: want it to parse, got {:?}", c.file, r);
        } else {
            match r {
                Ok(()) => panic!("{}: want code {:?}, but it parsed", c.file, c.code),
                Err(e) => assert_eq!(e.code, c.code, "{}: got {}", c.file, e),
            }
        }
    }

    fn lock_images() -> BTreeSet<String> {
        let v: Value = serde_json::from_slice(&read(&["node-workloads", "lock.json"])).unwrap();
        v["images"].as_object().expect("lock images").keys().cloned().collect()
    }

    #[test]
    fn node_workloads_fixtures() {
        let lock = lock_images();
        assert!(!lock.is_empty(), "lock.json lists no images");
        let cases = load_cases("node-workloads");
        let mut rows = 0;
        for c in &cases {
            let addon = c.addon.as_deref().unwrap_or(TEST_ADDON);
            let r = validate_decl(&read(&["node-workloads", c.file.as_str()]), addon, &lock);
            if c.valid {
                if let Ok(nw) = &r {
                    assert!(!nw.workloads.is_empty(), "{}: parsed with no workloads", c.file);
                }
            }
            check(c, r.map(|_| ()));
            rows += 1;
        }
        assert!(rows > 0 && rows == cases.len(), "ran {rows} rows");
    }

    #[test]
    fn model_set_fixtures() {
        let cases = load_cases("model-sets");
        let mut rows = 0;
        for c in &cases {
            let r = validate_model_set(&read(&["model-sets", c.file.as_str()]));
            if c.valid {
                if let Ok(m) = &r {
                    assert!(!m.id.is_empty(), "{}: parsed but is empty", c.file);
                }
            }
            check(c, r.map(|_| ()));
            rows += 1;
        }
        assert!(rows > 0 && rows == cases.len(), "ran {rows} rows");
    }

    #[test]
    fn desired_fixtures() {
        let cases = load_cases("desired");
        let mut rows = 0;
        for c in &cases {
            let r = validate_desired(&read(&["desired", c.file.as_str()]), TEST_AGENT_CN);
            let mut count = None;
            let mut outcome = r.as_ref().map(|_| ()).map_err(Clone::clone);
            if let Ok(es) = &r {
                count = Some(es.len());
                if let Some(set) = c.set.as_deref().filter(|s| !s.is_empty()) {
                    // The entry cannot see the set; the pairing is judged by
                    // check_profile.
                    let parts: Vec<&str> = set.split('/').collect();
                    let ms = validate_model_set(&read(&parts))
                        .unwrap_or_else(|e| panic!("{}: paired set {set}: {e}", c.file));
                    assert_eq!(es.len(), 1, "{}: paired with a set but not one entry", c.file);
                    outcome = check_profile(&es[0], &ms);
                }
            }
            check(c, outcome);
            if c.valid && c.file != "valid-empty.json" {
                assert!(count.unwrap_or(0) > 0, "{}: parsed but returned no entries", c.file);
            }
            rows += 1;
        }
        assert!(rows > 0 && rows == cases.len(), "ran {rows} rows");
    }

    #[test]
    fn desired_decl_invalid_carries_the_inner_code() {
        let e = validate_desired(&read(&["desired", "refuse-decl-uid-zero.json"]), TEST_AGENT_CN)
            .unwrap_err();
        assert_eq!(e.code, code::DECL_INVALID);
        assert_eq!(e.inner, Some(code::UID_INVALID));
    }

    #[test]
    fn desired_example_is_one_provisioned_and_one_running() {
        let es = validate_desired(&read(&["desired-node-workloads.json"]), TEST_AGENT_CN).unwrap();
        assert_eq!(es.len(), 2);
        assert_eq!(es[0].state, STATE_PROVISIONED);
        assert_eq!(es[1].state, STATE_RUNNING);
        assert!(es[0].reservation.is_none() && es[1].reservation.is_some());
    }

    #[test]
    fn the_artifact_names_its_own_addon_image_digest_and_a_known_arch() {
        let d = format!("sha256:{}", "ab".repeat(32));
        let good = format!("noo-addon-wl_rhaddon_addon-worker_{}_amd64.tar", "ab".repeat(32));
        assert!(artifact_ok(&good, "rhaddon", "addon-worker", &d));
        assert!(artifact_ok(&good.replace("amd64", "arm64"), "rhaddon", "addon-worker", &d));
        for bad in [
            good.replace("amd64", "riscv64"),
            good.replace("rhaddon", "other"),
            good.replace("addon-worker", "other-image"),
            good.replace(&"ab".repeat(32), &"cd".repeat(32)),
            good.replace(".tar", ".tgz"),
            format!("../{good}"),
        ] {
            assert!(!artifact_ok(&bad, "rhaddon", "addon-worker", &d), "{bad}");
        }
    }

    #[test]
    fn another_nodes_agent_is_not_admitted() {
        let e = validate_desired(&read(&["desired", "valid-running.json"]), "node-b").unwrap_err();
        assert_eq!(e.code, code::ADMIT_INVALID);
    }

    #[test]
    fn rhaddon_declaration_is_a_valid_fixture() {
        let nw = validate_decl(
            &read(&["node-workloads", "valid-rhaddon.json"]),
            "rhaddon",
            &lock_images(),
        )
        .unwrap();
        assert_eq!(nw.workloads.len(), 1);
        assert_eq!(nw.workloads[0].port, 9003);
    }

    #[test]
    fn every_code_a_fixture_names_is_produced() {
        // The reverse of "every case produces its code": every refusal code
        // the parsers can return has a fixture, so a code cannot exist unpinned.
        let mut want: HashSet<String> = HashSet::new();
        for dir in ["node-workloads", "model-sets"] {
            for c in load_cases(dir) {
                want.insert(c.code);
            }
        }
        for c in [
            code::BAD_JSON,
            code::UNKNOWN_FIELD,
            code::BAD_FORMAT,
            code::FIELD_MISSING,
            code::DUPLICATE_KEY,
            code::WORKLOADS_INVALID,
            code::DOOR_NAME_INVALID,
            code::DOOR_NAME_TOO_LONG,
            code::NAME_DUPLICATE,
            code::IMAGE_NOT_IN_LOCK,
            code::UID_INVALID,
            code::COMMAND_INVALID,
            code::PORT_INVALID,
            code::PROTOCOLS_INVALID,
            code::HEALTH_INVALID,
            code::DRAIN_INVALID,
            code::ACCEL_INVALID,
            code::MODEL_SLOT_INVALID,
            code::ENV_KEY_OUTSIDE_PREFIX,
            code::ENV_KEY_REFUSED_PREFIX,
            code::ENV_BOUND_INVALID,
            code::SCRATCH_TARGET_REFUSED,
            code::SCRATCH_INVALID,
            code::SCRATCH_IN_MODEL_SLOT,
            code::LIMITS_INVALID,
            code::ID_INVALID,
            code::REVISION_INVALID,
            code::KIND_INVALID,
            code::MODALITY_INVALID,
            code::RUNTIME_INVALID,
            code::SOURCE_INVALID,
            code::LICENSE_INVALID,
            code::PATH_INVALID,
            code::SHA256_INVALID,
            code::FILES_INVALID,
            code::NOTICE_NOT_IN_FILES,
            code::PROFILE_INVALID,
            code::ARCH_INVALID,
            code::FITS_REQUIRED,
            code::FITS_FORBIDDEN,
            code::FITS_INVALID,
            code::TRUST_REQUIRED,
        ] {
            assert!(want.contains(c), "no fixture produces {c:?}");
        }
        for c in load_cases("desired") {
            want.insert(c.code);
        }
        for c in [
            code::DECL_INVALID,
            code::DESIRED_INVALID,
            code::DOOR_LEAF_MISSING,
            code::IMAGE_MISSING,
            code::SET_MISSING,
            code::SET_SLOT_INVALID,
            code::ADMIT_INVALID,
            code::ENV_OUT_OF_BOUNDS,
            code::PROFILE_INVALID,
        ] {
            assert!(want.contains(c), "no desired fixture produces {c:?}");
        }
    }

    #[test]
    fn check_profile_realtime_and_names() {
        let set = ModelSet {
            id: "s".into(),
            needs: Needs {
                profiles: vec![
                    SetProfile {
                        name: "live".into(),
                        accel: "cuda".into(),
                        realtime: Some(true),
                        ..Default::default()
                    },
                    SetProfile {
                        name: "unstated".into(),
                        accel: "cuda".into(),
                        ..Default::default()
                    },
                    SetProfile {
                        name: "batch".into(),
                        accel: "cuda".into(),
                        realtime: Some(false),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        let entry = |profile: Option<&str>, realtime: bool| DesiredEntry {
            profile: profile.map(String::from),
            decl_parsed: Decl {
                accel: Accel { gpu: 1, realtime },
                ..Default::default()
            },
            ..Default::default()
        };
        let rows: [(&str, Option<&str>, bool, bool); 7] = [
            ("named realtime profile", Some("live"), true, true),
            ("realtime unstated counts as realtime", Some("unstated"), true, true),
            ("realtime:false profile, realtime workload", Some("batch"), true, false),
            ("realtime:false profile, other workload", Some("batch"), false, true),
            ("unknown name", Some("nope"), true, false),
            ("missing", None, true, false),
            ("empty", Some(""), true, false),
        ];
        for (name, profile, realtime, ok) in rows {
            let r = check_profile(&entry(profile, realtime), &set);
            if ok {
                assert!(r.is_ok(), "{name}: got {r:?}");
            } else {
                assert_eq!(r.unwrap_err().code, code::PROFILE_INVALID, "{name}");
            }
        }
    }

    #[test]
    fn compute_cap_is_numeric() {
        assert_eq!(compute_cap_at_least("10.0", "8.0"), Some(true));
        assert_eq!(compute_cap_at_least("8.10", "8.9"), Some(true));
        assert_eq!(compute_cap_at_least("8.6", "8.0"), Some(true));
        assert_eq!(compute_cap_at_least("8.0", "8.0"), Some(true));
        assert_eq!(compute_cap_at_least("7.5", "8.0"), Some(false));
        assert_eq!(compute_cap_at_least("8.9", "8.10"), Some(false));
        assert_eq!(compute_cap_at_least("9.0", "8.9"), Some(true));
        assert_eq!(compute_cap_at_least("x", "8.0"), None);
        for bad in [
            ("", "8.0"),
            ("8", "8.0"),
            ("abc", "8.0"),
            ("8.0", "x.y"),
            ("8.0.1", "8.0"),
            ("-1.0", "8.0"),
            ("8.6", ""),
        ] {
            assert_eq!(compute_cap_at_least(bad.0, bad.1), None, "{bad:?}");
        }
    }

    /// Test JSON is written with parentheses for braces so that no bare brace
    /// sits in a string literal (the source guard counts braces).
    fn obj(s: &str) -> String {
        s.replace('(', "\u{7b}").replace(')', "\u{7d}")
    }

    #[test]
    fn duplicate_key_is_refused_at_any_depth() {
        // Two levels down in a model set.
        let nested = obj(r#"(
            "source": ("local": ("verified": true, "verified": false))
        )"#);
        let e = validate_model_set(nested.as_bytes()).unwrap_err();
        assert_eq!(e.code, code::DUPLICATE_KEY, "{e}");
        // Inside an array element, two levels down in a declaration.
        let decl = obj(r#"(
            "format": "noo-addon-node-workloads/1",
            "workloads": [("name": "a", "health": ("ready": "/a", "ready": "/b"))]
        )"#);
        let e = validate_decl(decl.as_bytes(), TEST_ADDON, &lock_images()).unwrap_err();
        assert_eq!(e.code, code::DUPLICATE_KEY, "{e}");
        // In a map-typed field (env), which serde would collapse silently.
        let env = obj(r#"(
            "format": "noo-addon-node-workloads/1",
            "workloads": [("name": "a", "env": ("RHADDON_X": ("min": 1), "RHADDON_X": ("min": 2)))]
        )"#);
        let e = validate_decl(env.as_bytes(), TEST_ADDON, &lock_images()).unwrap_err();
        assert_eq!(e.code, code::DUPLICATE_KEY, "{e}");
        // The same key in sibling objects is not a repeat.
        let sibling = obj(r#"("a": ("x": 1), "b": ("x": 2))"#);
        let e = validate_model_set(sibling.as_bytes()).unwrap_err();
        assert_eq!(e.code, code::UNKNOWN_FIELD, "{e}");
    }

    #[test]
    fn null_is_refused_outside_the_named_nullable_fields() {
        // A null on a decl field is field_type, never read as its zero value.
        let decl = obj(r#"(
            "format": "noo-addon-node-workloads/1",
            "workloads": [("name": "a", "accel": ("gpu": null))]
        )"#);
        let e = validate_decl(decl.as_bytes(), TEST_ADDON, &lock_images()).unwrap_err();
        assert_eq!(e.code, code::FIELD_TYPE, "{e}");
        // In desired-config, null comes back as field_type ITSELF, even on a
        // decl field nested inside an entry (not desired_invalid, not
        // decl_invalid), because the whole fragment is walked first.
        let frag = obj(r#"("node_workloads": [("decl": ("uid": null))])"#);
        let e = validate_desired(frag.as_bytes(), "node-a").unwrap_err();
        assert_eq!(e.code, code::FIELD_TYPE, "{e}");
        // The one nullable field passes the walk.
        let ok = obj(r#"("node_workloads": [("reservation": null)])"#);
        let v: Value = serde_json::from_str(&ok).unwrap();
        assert!(check_nulls_value(&v, NULLABLE_DESIRED).is_ok());
        // `*` is an array index only: an object key "0" is not one.
        let keyed = obj(r#"("node_workloads": ("0": ("reservation": null)))"#);
        let v: Value = serde_json::from_str(&keyed).unwrap();
        assert_eq!(check_nulls_value(&v, NULLABLE_DESIRED).unwrap_err().code, code::FIELD_TYPE);
        // Judged from the document root: the entry pattern does not match
        // the same key one level down.
        let deep = obj(r#"("x": ("reservation": null))"#);
        let v: Value = serde_json::from_str(&deep).unwrap();
        assert!(check_nulls_value(&v, NULLABLE_ENTRY).is_err());
        // A document that does not parse is left to the typed decode.
        assert_eq!(validate_model_set(b"not json").unwrap_err().code, code::BAD_JSON);
    }

    #[test]
    fn serde_errors_map_to_the_contract_codes() {
        let code_of = |s: &str| validate_model_set(s.as_bytes()).unwrap_err().code;
        assert_eq!(code_of("not json"), code::BAD_JSON);
        assert_eq!(code_of(""), code::BAD_JSON);
        assert_eq!(code_of(&obj(r#"("format": "x") trailing"#)), code::BAD_JSON);
        assert_eq!(code_of(&obj(r#"("nope": 1)"#)), code::UNKNOWN_FIELD);
        assert_eq!(code_of(&obj(r#"("format": 1)"#)), code::FIELD_TYPE);
        assert_eq!(code_of(&obj(r#"("format": "noo-model-set/1")"#)), code::FIELD_MISSING);
    }

    #[test]
    fn set_path_rule() {
        let rows: [(&str, bool); 14] = [
            ("model.safetensors", true),
            ("voices/a.pt", true),
            (".hidden", true),
            ("", false),
            ("/abs", false),
            (".", false),
            ("..", false),
            ("a/..", false),
            ("../a", false),
            ("a/b/c", false),
            ("a//b", false),
            ("a/", false),
            ("sp ace", false),
            ("\u{fc}", false),
        ];
        for (p, want) in rows {
            assert_eq!(valid_set_path(p), want, "valid_set_path({p:?})");
        }
    }

    #[test]
    fn door_name_boundary() {
        assert_eq!(env_prefix("rh-addon"), "RH_ADDON_");
        assert_eq!("noo-stunnel-".len() + MAX_DOOR_NAMES, 63);
    }

    #[test]
    fn reasons_are_unique() {
        let mut seen = HashSet::new();
        for r in code::REASONS {
            assert!(seen.insert(*r), "reason {r:?} twice");
        }
    }
}
