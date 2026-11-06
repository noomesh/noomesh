// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The validator for a model set's manifest, `model-set.json`
//! (`noo-model-set/1`, i300 F2b).
//!
//! It is a port of the node agent's reference validator
//! (`node-agent-go/internal/nodewl/modelset.go`) and judges the SAME
//! fixtures (`src/addons/testdata/i300/model-sets`, a byte-identical copy of
//! `tests/fixtures/i300/model-sets`; `cases.json` names the refusal code for
//! each file). The codes are the contract, the detail text is for people.
//!
//! The order of the checks is the Go validator's, and the first refusal wins:
//!
//! 1. the document is walked once: a repeated object key is `duplicate_key`
//!    and a JSON null anywhere is `field_type` (this format has no nullable
//!    field, `docs/reference/node-workloads.md`), and so is a syntax error
//!    (`bad_json`) or data after the document;
//! 2. the shape: an unknown field is `unknown_field`, a value of the wrong
//!    JSON type is `field_type`;
//! 3. a required key that is absent is `field_missing`;
//! 4. the values (`id_invalid`, `source_invalid`, ...).
//!
//! The CLI validates the manifest it is about to write and refuses to write
//! an invalid one: a set the node agent would refuse must not be signed.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// The `format` of a model-set.json.
pub const FORMAT: &str = "noo-model-set/1";

/// A refusal: a stable code and a human sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub detail: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

type R<T> = Result<T, Refusal>;

fn refuse<T>(code: &'static str, detail: impl Into<String>) -> R<T> {
    Err(Refusal { code, detail: detail.into() })
}

// ── Step 1: the walk (duplicate keys, nulls, syntax) ───────────────────

const DUP_MARK: &str = "@duplicate-key:";
const NULL_MARK: &str = "@null";

/// A JSON value read the strict way: it fails on a repeated key and on null.
struct Checked(Value);

impl<'de> Deserialize<'de> for Checked {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Checked;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any JSON value")
            }

            fn visit_bool<E: de::Error>(self, b: bool) -> Result<Checked, E> {
                Ok(Checked(Value::Bool(b)))
            }

            fn visit_i64<E: de::Error>(self, n: i64) -> Result<Checked, E> {
                Ok(Checked(Value::from(n)))
            }

            fn visit_u64<E: de::Error>(self, n: u64) -> Result<Checked, E> {
                Ok(Checked(Value::from(n)))
            }

            fn visit_f64<E: de::Error>(self, n: f64) -> Result<Checked, E> {
                Ok(Checked(Value::from(n)))
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<Checked, E> {
                Ok(Checked(Value::String(s.to_owned())))
            }

            fn visit_unit<E: de::Error>(self) -> Result<Checked, E> {
                Err(E::custom(NULL_MARK))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Checked, A::Error> {
                let mut out = Vec::new();
                while let Some(Checked(v)) = seq.next_element::<Checked>()? {
                    out.push(v);
                }
                Ok(Checked(Value::Array(out)))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Checked, A::Error> {
                let mut out = Map::new();
                while let Some(k) = map.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(de::Error::custom(format!("{DUP_MARK}{k}")));
                    }
                    let Checked(v) = map.next_value::<Checked>()?;
                    out.insert(k, v);
                }
                Ok(Checked(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}

/// Parse one JSON document the strict way: a repeated key is `duplicate_key`,
/// a null is `field_type`, a syntax error or trailing data is `bad_json`.
pub fn parse_strict(bytes: &[u8]) -> R<Value> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = match Checked::deserialize(&mut de) {
        Ok(Checked(v)) => v,
        Err(e) => {
            let msg = e.to_string();
            if let Some(rest) = msg.strip_prefix(DUP_MARK) {
                let key = rest.split(" at line ").next().unwrap_or(rest);
                return refuse("duplicate_key", format!("key {key:?} is repeated in an object"));
            }
            if msg.starts_with(NULL_MARK) {
                return refuse(
                    "field_type",
                    "JSON null (null is refused: this format has no nullable field)",
                );
            }
            return refuse("bad_json", msg);
        }
    };
    if de.end().is_err() {
        return refuse("bad_json", "data after the JSON document");
    }
    Ok(value)
}

// ── Step 2: the shape ──────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Ty {
    Str,
    Int,
    Bool,
}

fn as_obj<'a>(v: &'a Value, at: &str) -> R<&'a Map<String, Value>> {
    match v.as_object() {
        Some(m) => Ok(m),
        None => refuse("field_type", format!("{at} must be an object")),
    }
}

fn keys_ok(m: &Map<String, Value>, at: &str, allowed: &[&str]) -> R<()> {
    for k in m.keys() {
        if !allowed.contains(&k.as_str()) {
            return refuse("unknown_field", format!("{at}: unknown field {k:?}"));
        }
    }
    Ok(())
}

fn typed(m: &Map<String, Value>, at: &str, key: &str, t: Ty) -> R<()> {
    let Some(v) = m.get(key) else { return Ok(()) };
    let ok = match t {
        Ty::Str => v.is_string(),
        Ty::Int => v.is_i64(),
        Ty::Bool => v.is_boolean(),
    };
    if ok {
        Ok(())
    } else {
        refuse("field_type", format!("{at}.{key} has the wrong JSON type"))
    }
}

fn typed_all(m: &Map<String, Value>, at: &str, keys: &[&str], t: Ty) -> R<()> {
    for k in keys {
        typed(m, at, k, t)?;
    }
    Ok(())
}

fn items<'a>(m: &'a Map<String, Value>, at: &str, key: &str) -> R<Vec<&'a Value>> {
    match m.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => Ok(a.iter().collect()),
        Some(_) => refuse("field_type", format!("{at}.{key} must be an array")),
    }
}

fn str_list<'a>(m: &'a Map<String, Value>, at: &str, key: &str) -> R<Vec<&'a str>> {
    let mut out = Vec::new();
    for v in items(m, at, key)? {
        match v.as_str() {
            Some(s) => out.push(s),
            None => return refuse("field_type", format!("{at}.{key} holds a non-string")),
        }
    }
    Ok(out)
}

fn sub<'a>(
    m: &'a Map<String, Value>,
    at: &str,
    key: &str,
    allowed: &[&str],
) -> R<Option<&'a Map<String, Value>>> {
    let Some(v) = m.get(key) else { return Ok(None) };
    let here = format!("{at}.{key}");
    let o = as_obj(v, &here)?;
    keys_ok(o, &here, allowed)?;
    Ok(Some(o))
}

const TOP: &[&str] = &[
    "format", "id", "revision", "kind", "modality", "runtime", "source", "license", "files",
    "needs", "fits", "trust",
];

fn shape(root: &Value) -> R<&Map<String, Value>> {
    let top = "model-set.json";
    let m = as_obj(root, top)?;
    keys_ok(m, top, TOP)?;
    typed_all(m, top, &["format", "id", "revision", "kind", "modality"], Ty::Str)?;
    str_list(m, top, "runtime")?;
    if let Some(src) = sub(m, top, "source", &["hf", "local"])? {
        if let Some(hf) = sub(src, "source", "hf", &["repo", "ref", "digests"])? {
            typed_all(hf, "source.hf", &["repo", "ref", "digests"], Ty::Str)?;
        }
        if let Some(l) = sub(src, "source", "local", &["verified"])? {
            typed(l, "source.local", "verified", Ty::Bool)?;
        }
    }
    let lic_keys = ["id", "url", "accept", "accepted", "notice_files", "additional"];
    if let Some(lic) = sub(m, top, "license", &lic_keys)? {
        typed_all(lic, "license", &["id", "url", "accept"], Ty::Str)?;
        if let Some(acc) = sub(lic, "license", "accepted", &["by", "at"])? {
            typed_all(acc, "license.accepted", &["by", "at"], Ty::Str)?;
        }
        str_list(lic, "license", "notice_files")?;
        for a in items(lic, "license", "additional")? {
            let o = as_obj(a, "license.additional[]")?;
            keys_ok(o, "license.additional[]", &["id", "url", "notice_path"])?;
            typed_all(o, "license.additional[]", &["id", "url", "notice_path"], Ty::Str)?;
        }
    }
    for f in items(m, top, "files")? {
        let o = as_obj(f, "files[]")?;
        keys_ok(o, "files[]", &["path", "bytes", "sha256", "role", "from_archive"])?;
        typed_all(o, "files[]", &["path", "sha256", "role"], Ty::Str)?;
        typed(o, "files[]", "bytes", Ty::Int)?;
        if let Some(a) = sub(o, "files[]", "from_archive", &["path", "sha256", "bytes"])? {
            typed_all(a, "files[].from_archive", &["path", "sha256"], Ty::Str)?;
            typed(a, "files[].from_archive", "bytes", Ty::Int)?;
        }
    }
    let needs_keys = ["profiles", "cpu_fallback", "arch"];
    if let Some(n) = sub(m, top, "needs", &needs_keys)? {
        typed(n, "needs", "cpu_fallback", Ty::Bool)?;
        str_list(n, "needs", "arch")?;
        let pk = [
            "name", "accel", "min_compute", "vram_mb", "ram_mb", "per_slot_vram_mb", "realtime",
        ];
        for p in items(n, "needs", "profiles")? {
            let o = as_obj(p, "needs.profiles[]")?;
            keys_ok(o, "needs.profiles[]", &pk)?;
            typed_all(o, "needs.profiles[]", &["name", "accel", "min_compute"], Ty::Str)?;
            typed_all(o, "needs.profiles[]", &["vram_mb", "ram_mb", "per_slot_vram_mb"], Ty::Int)?;
            typed(o, "needs.profiles[]", "realtime", Ty::Bool)?;
        }
    }
    if let Some(f) = sub(m, top, "fits", &["model", "revision", "runtime"])? {
        typed_all(f, "fits", &["model", "revision", "runtime"], Ty::Str)?;
    }
    if let Some(t) = sub(m, top, "trust", &["by", "at", "reason"])? {
        typed_all(t, "trust", &["by", "at", "reason"], Ty::Str)?;
    }
    Ok(m)
}

// ── Step 3: required keys ──────────────────────────────────────────────

fn require(v: Option<&Value>, at: &str, keys: &[&str]) -> R<()> {
    let Some(Value::Object(m)) = v else { return Ok(()) };
    for k in keys {
        if !m.contains_key(*k) {
            return refuse("field_missing", format!("{at}: `{k}` is required"));
        }
    }
    Ok(())
}

fn required(m: &Map<String, Value>) -> R<()> {
    let top = [
        "format", "id", "revision", "kind", "modality", "runtime", "source", "license", "files",
        "needs",
    ];
    for k in top {
        if !m.contains_key(k) {
            return refuse("field_missing", format!("model-set.json: `{k}` is required"));
        }
    }
    require(m.get("license"), "license", &["id", "url", "accept"])?;
    require(m.get("needs"), "needs", &["profiles", "cpu_fallback", "arch"])?;
    let src = m.get("source").and_then(Value::as_object);
    require(src.and_then(|s| s.get("hf")), "source.hf", &["repo", "ref", "digests"])?;
    require(src.and_then(|s| s.get("local")), "source.local", &["verified"])?;
    if let Some(Value::Array(files)) = m.get("files") {
        for f in files {
            require(Some(f), "files[]", &["path", "bytes", "sha256"])?;
            let archive = f.get("from_archive");
            require(archive, "files[].from_archive", &["path", "sha256", "bytes"])?;
        }
    }
    let profiles = m.get("needs").and_then(|n| n.get("profiles"));
    if let Some(Value::Array(ps)) = profiles {
        for p in ps {
            require(Some(p), "needs.profiles[]", &["name", "accel"])?;
        }
    }
    Ok(())
}

// ── Pattern helpers (the Go validator's regular expressions) ───────────

fn all_in(s: &str, extra: &[u8]) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

/// `^[a-z0-9][a-z0-9._-]{0,63}$`: a set id and a runtime string.
pub fn id_ok(s: &str) -> bool {
    let first = s.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let rest = s.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
    });
    first && rest && s.len() <= 64
}

/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`: a revision.
pub fn revision_ok(s: &str) -> bool {
    let first = s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric());
    first && all_in(s, b"._-") && s.len() <= 128
}

fn profile_name_ok(s: &str) -> bool {
    let first = s.bytes().next().is_some_and(|b| b.is_ascii_lowercase());
    let rest = s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    first && rest && s.len() <= 32
}

fn compute_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |x: &[u8]| !x.is_empty() && x.iter().all(u8::is_ascii_digit);
    match b.iter().position(|c| *c == b'.') {
        Some(i) => (i == 1 || i == 2) && digits(&b[..i]) && b.len() == i + 2 && digits(&b[i + 1..]),
        None => false,
    }
}

fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A 64-character lower-case hex sha256.
pub fn sha256_ok(s: &str) -> bool {
    lower_hex(s, 64)
}

/// A 40-character lower-case hex commit.
pub fn commit_ok(s: &str) -> bool {
    lower_hex(s, 40)
}

fn repo_part_ok(s: &str) -> bool {
    let first = s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric());
    first && all_in(s, b"._-") && s.len() <= 96
}

/// `<org>/<name>` on Hugging Face.
pub fn hf_repo_ok(s: &str) -> bool {
    match s.split_once('/') {
        Some((a, b)) => repo_part_ok(a) && repo_part_ok(b),
        None => false,
    }
}

fn license_id_ok(s: &str) -> bool {
    let first = s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric());
    first && all_in(s, b"._+-") && s.len() <= 64
}

/// `^https://\S{1,500}$`.
pub fn https_url_ok(s: &str) -> bool {
    match s.strip_prefix("https://") {
        Some(rest) => {
            let n = rest.chars().count();
            (1..=500).contains(&n) && !rest.chars().any(|c| c.is_ascii_whitespace())
        }
        None => false,
    }
}

/// The file path rule of a model set: relative, no `.` or `..` component, at
/// most one directory level, charset `[A-Za-z0-9._-]`.
pub fn valid_set_path(p: &str) -> bool {
    if p.is_empty() || p.len() > 129 {
        return false;
    }
    let comps: Vec<&str> = p.split('/').collect();
    if comps.len() > 2 {
        return false;
    }
    comps.iter().all(|c| !c.is_empty() && *c != "." && *c != ".." && all_in(c, b"._-"))
}

fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if y & 3 == 0 && (y.rem_euclid(100) != 0 || y.rem_euclid(400) == 0) {
                29
            } else {
                28
            }
        }
    }
}

fn parse_rfc3339(s: &str) -> Option<()> {
    let b = s.as_bytes();
    let punct_ok = b.len() >= 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':';
    if !punct_ok {
        return None;
    }
    let num = |a: usize, z: usize| -> Option<u32> {
        let t = s.get(a..z)?;
        if t.bytes().all(|c| c.is_ascii_digit()) {
            t.parse::<u32>().ok()
        } else {
            None
        }
    };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    if !(1..=days_in_month(y, mo)).contains(&d) {
        return None;
    }
    let mut rest = s.get(19..)?;
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return None;
        }
        rest = frac.get(n..)?;
    }
    if rest == "Z" {
        return Some(());
    }
    let rb = rest.as_bytes();
    if rb.len() != 6 || (rb[0] != b'+' && rb[0] != b'-') || rb[3] != b':' {
        return None;
    }
    let off = |a: usize, z: usize| -> Option<u32> {
        let t = rest.get(a..z)?;
        if t.bytes().all(|c| c.is_ascii_digit()) {
            t.parse::<u32>().ok()
        } else {
            None
        }
    };
    if off(1, 3)? > 23 || off(4, 6)? > 59 {
        return None;
    }
    Some(())
}

/// An RFC 3339 timestamp, as `license.accepted.at` and `trust.at` require.
pub fn rfc3339(s: &str) -> bool {
    parse_rfc3339(s).is_some()
}

// ── Step 4: the values ─────────────────────────────────────────────────

fn text<'a>(m: &'a Map<String, Value>, key: &str) -> &'a str {
    m.get(key).and_then(Value::as_str).unwrap_or("")
}

fn object<'a>(m: &'a Map<String, Value>, key: &str) -> R<&'a Map<String, Value>> {
    match m.get(key).and_then(Value::as_object) {
        Some(o) => Ok(o),
        None => refuse("field_missing", format!("`{key}` is required")),
    }
}

fn check_source(src: &Map<String, Value>) -> R<()> {
    let hf = src.get("hf").and_then(Value::as_object);
    if hf.is_some() == src.contains_key("local") {
        return refuse("source_invalid", "source takes exactly one of hf and local");
    }
    if let Some(hf) = hf {
        if !hf_repo_ok(text(hf, "repo")) || !commit_ok(text(hf, "ref")) {
            return refuse(
                "source_invalid",
                "source.hf needs repo <org>/<name> and a 40-hex commit ref",
            );
        }
        let d = text(hf, "digests");
        if d != "authenticated" && d != "operator-trusted-local" {
            return refuse("source_invalid", format!("source.hf.digests {d:?}"));
        }
    }
    Ok(())
}

fn check_license(l: &Map<String, Value>) -> R<()> {
    if !license_id_ok(text(l, "id")) || !https_url_ok(text(l, "url")) {
        return refuse("license_invalid", "license id or url");
    }
    let accept = text(l, "accept");
    if accept != "none" && accept != "operator" {
        return refuse("license_invalid", format!("license.accept {accept:?}"));
    }
    if let Some(acc) = l.get("accepted").and_then(Value::as_object) {
        let by = text(acc, "by");
        if accept == "none" || by.is_empty() || by.len() > 128 || !rfc3339(text(acc, "at")) {
            return refuse(
                "license_invalid",
                "license.accepted needs accept=operator, by and an RFC 3339 at",
            );
        }
    }
    let extra: Vec<&Value> = match l.get("additional") {
        Some(Value::Array(a)) => a.iter().collect(),
        _ => Vec::new(),
    };
    if extra.len() > 8 {
        let n = extra.len();
        return refuse("license_invalid", format!("{n} additional licenses (at most 8)"));
    }
    for a in extra {
        let ok = a.as_object().is_some_and(|o| {
            license_id_ok(text(o, "id")) && https_url_ok(text(o, "url"))
        });
        if !ok {
            return refuse("license_invalid", "license.additional id or url");
        }
    }
    Ok(())
}

fn check_files(m: &Map<String, Value>) -> R<()> {
    let files: Vec<&Value> = match m.get("files") {
        Some(Value::Array(a)) => a.iter().collect(),
        _ => Vec::new(),
    };
    if files.is_empty() || files.len() > 64 {
        return refuse("files_invalid", format!("{} files (1..64)", files.len()));
    }
    let mut have: Vec<&str> = Vec::new();
    let mut notice_paths: Vec<&str> = Vec::new();
    for f in files {
        let Some(o) = f.as_object() else {
            return refuse("field_type", "files[] must be an object");
        };
        let path = text(o, "path");
        if !valid_set_path(path) {
            return refuse("path_invalid", format!("file path {path:?}"));
        }
        if !sha256_ok(text(o, "sha256")) {
            return refuse("sha256_invalid", format!("{path}: sha256 is not 64 lower-case hex"));
        }
        let bytes = o.get("bytes").and_then(Value::as_i64).unwrap_or(0);
        if !(1..=(1i64 << 40)).contains(&bytes) {
            return refuse("files_invalid", format!("{path}: bytes {bytes}"));
        }
        let role = text(o, "role");
        if !matches!(role, "" | "weights" | "notice" | "config") {
            return refuse("files_invalid", format!("{path}: role {role:?}"));
        }
        if let Some(a) = o.get("from_archive").and_then(Value::as_object) {
            let ab = a.get("bytes").and_then(Value::as_i64).unwrap_or(0);
            if !valid_set_path(text(a, "path"))
                || !sha256_ok(text(a, "sha256"))
                || !(1..=(1i64 << 40)).contains(&ab)
            {
                return refuse(
                    "from_archive_invalid",
                    format!("{path}: from_archive needs a set path, a lower-case sha256 and bytes"),
                );
            }
            if role == "notice" {
                return refuse(
                    "from_archive_invalid",
                    format!("{path}: a notice file is staged as itself, not extracted"),
                );
            }
        }
        if have.contains(&path) {
            return refuse("files_invalid", format!("path {path:?} is listed twice"));
        }
        have.push(path);
        if role == "notice" {
            notice_paths.push(path);
        }
    }
    let lic = object(m, "license")?;
    if let Some(Value::Array(extra)) = lic.get("additional") {
        for a in extra.iter().filter_map(Value::as_object) {
            let np = text(a, "notice_path");
            if np.is_empty() {
                continue;
            }
            let at = format!("license.additional {}: notice_path {np:?}", text(a, "id"));
            if !valid_set_path(np) {
                return refuse("path_invalid", at);
            }
            if !notice_paths.contains(&np) {
                return refuse("notice_not_in_files", format!("{at} is not a role notice file"));
            }
        }
    }
    let notices: Vec<&str> = match lic.get("notice_files") {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if notices.len() > 16 {
        return refuse("license_invalid", format!("{} notice files (at most 16)", notices.len()));
    }
    for n in notices {
        if !valid_set_path(n) {
            return refuse("path_invalid", format!("notice path {n:?}"));
        }
        if !have.contains(&n) {
            return refuse(
                "notice_not_in_files",
                format!("license.notice_files names {n:?}, which is not in files"),
            );
        }
    }
    Ok(())
}

fn check_needs(n: &Map<String, Value>) -> R<()> {
    let profiles: Vec<&Value> = match n.get("profiles") {
        Some(Value::Array(a)) => a.iter().collect(),
        _ => Vec::new(),
    };
    if profiles.is_empty() || profiles.len() > 8 {
        return refuse("profile_invalid", format!("{} profiles (1..8)", profiles.len()));
    }
    for p in profiles {
        let Some(o) = p.as_object() else {
            return refuse("field_type", "needs.profiles[] must be an object");
        };
        let name = text(o, "name");
        let accel = text(o, "accel");
        if !profile_name_ok(name) || (accel != "cuda" && accel != "cpu") {
            return refuse("profile_invalid", format!("profile {name:?}: name or accel"));
        }
        let mc = text(o, "min_compute");
        if !mc.is_empty() && !compute_ok(mc) {
            return refuse("profile_invalid", format!("profile {name:?}: min_compute {mc:?}"));
        }
        for k in ["vram_mb", "ram_mb", "per_slot_vram_mb"] {
            if let Some(v) = o.get(k).and_then(Value::as_i64) {
                if !(1..=4_194_304).contains(&v) {
                    return refuse(
                        "profile_invalid",
                        format!("profile {name:?}: a size is out of range"),
                    );
                }
            }
        }
    }
    let arch: Vec<&str> = match n.get("arch") {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if arch.is_empty() || arch.len() > 4 {
        return refuse("arch_invalid", format!("{} arch entries (1..4)", arch.len()));
    }
    for a in arch {
        if a != "amd64" && a != "arm64" {
            return refuse("arch_invalid", format!("arch {a:?}"));
        }
    }
    Ok(())
}

fn check_fits(m: &Map<String, Value>) -> R<()> {
    let pack = text(m, "kind") == "voice-pack";
    let fits = m.get("fits").and_then(Value::as_object);
    if pack && fits.is_none() {
        return refuse("fits_required", "a voice-pack states what it fits");
    }
    if !pack && fits.is_some() {
        return refuse("fits_forbidden", "fits is for voice-pack only");
    }
    let Some(f) = fits else { return Ok(()) };
    let (model, rev, runtime) = (text(f, "model"), text(f, "revision"), text(f, "runtime"));
    let (by_model, by_runtime) = (!model.is_empty(), !runtime.is_empty());
    if by_model == by_runtime || (by_runtime && !rev.is_empty()) {
        return refuse("fits_invalid", "fits is {model[, revision]} or {runtime}");
    }
    if by_model && (!id_ok(model) || (!rev.is_empty() && !revision_ok(rev))) {
        return refuse("fits_invalid", "fits.model or fits.revision is malformed");
    }
    if by_runtime && !id_ok(runtime) {
        return refuse("fits_invalid", "fits.runtime is malformed");
    }
    Ok(())
}

fn check_trust(m: &Map<String, Value>) -> R<()> {
    let src = object(m, "source")?;
    let hf_untrusted = src
        .get("hf")
        .and_then(Value::as_object)
        .is_some_and(|h| text(h, "digests") == "operator-trusted-local");
    let local_unverified = src
        .get("local")
        .and_then(Value::as_object)
        .is_some_and(|l| l.get("verified").and_then(Value::as_bool) == Some(false));
    let trust = m.get("trust").and_then(Value::as_object);
    if (hf_untrusted || local_unverified) && trust.is_none() {
        return refuse(
            "trust_required",
            "digests were not authenticated upstream: trust {by, at, reason} is required",
        );
    }
    if let Some(t) = trust {
        let (by, reason) = (text(t, "by"), text(t, "reason"));
        let who_ok = !by.is_empty() && by.len() <= 128;
        let why_ok = !reason.is_empty() && reason.len() <= 500;
        if !who_ok || !why_ok || !rfc3339(text(t, "at")) {
            return refuse("trust_invalid", "trust needs by, an RFC 3339 at and a reason");
        }
    }
    Ok(())
}

fn check_set(m: &Map<String, Value>) -> R<()> {
    let format = text(m, "format");
    if format != FORMAT {
        return refuse("bad_format", format!("format is {format:?}, want {FORMAT:?}"));
    }
    if !id_ok(text(m, "id")) {
        return refuse("id_invalid", format!("id {:?}", text(m, "id")));
    }
    if !revision_ok(text(m, "revision")) {
        return refuse("revision_invalid", format!("revision {:?}", text(m, "revision")));
    }
    let kind = text(m, "kind");
    if kind != "voice" && kind != "voice-pack" {
        return refuse("kind_invalid", format!("kind {kind:?}"));
    }
    let modality = text(m, "modality");
    if !matches!(modality, "speech-to-speech" | "stt" | "tts") {
        return refuse("modality_invalid", format!("modality {modality:?}"));
    }
    let runtime: Vec<&str> = match m.get("runtime") {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if runtime.is_empty() || runtime.len() > 8 {
        return refuse("runtime_invalid", format!("{} runtime strings (1..8)", runtime.len()));
    }
    for r in runtime {
        if !id_ok(r) {
            return refuse("runtime_invalid", format!("runtime {r:?}"));
        }
    }
    check_source(object(m, "source")?)?;
    check_license(object(m, "license")?)?;
    check_files(m)?;
    check_needs(object(m, "needs")?)?;
    check_fits(m)?;
    check_trust(m)
}

/// Validate the exact bytes of a `model-set.json` (after any signature over
/// them has been checked). The first refusal wins.
pub fn validate(bytes: &[u8]) -> Result<(), Refusal> {
    let root = parse_strict(bytes)?;
    let m = shape(&root)?;
    required(m)?;
    check_set(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/addons/testdata/i300/model-sets")
    }

    fn cases() -> Vec<Value> {
        let raw = std::fs::read(dir().join("cases.json")).expect("cases.json");
        let v: Value = serde_json::from_slice(&raw).expect("cases.json is JSON");
        v.as_array().expect("cases.json is an array").clone()
    }

    #[test]
    fn every_fixture_gets_the_code_cases_json_pins() {
        let cases = cases();
        assert!(cases.len() >= 40, "the case list was not read: {} cases", cases.len());
        let mut refused = 0;
        let mut accepted = 0;
        // Every mismatch is collected, so a failing run names each fixture.
        let mut mismatches: Vec<String> = Vec::new();
        for c in &cases {
            let file = c["file"].as_str().expect("file");
            let want = c["code"].as_str().expect("code");
            let valid = c["valid"].as_bool().expect("valid");
            let bytes = std::fs::read(dir().join(file)).expect("fixture");
            match validate(&bytes) {
                Ok(()) => {
                    if !valid {
                        mismatches.push(format!("{file}: expected refused with {want}, got ok"));
                    }
                    accepted += 1;
                }
                Err(r) => {
                    if valid {
                        mismatches.push(format!("{file}: expected ok, got {} ({r})", r.code));
                    } else if r.code != want {
                        let got = r.code;
                        mismatches.push(format!("{file}: expected {want}, got {got} ({r})"));
                    }
                    refused += 1;
                }
            }
        }
        let n = mismatches.len();
        assert!(mismatches.is_empty(), "{n} mismatches:\n{}", mismatches.join("\n"));
        assert!(accepted >= 7 && refused >= 30, "accepted {accepted}, refused {refused}");
    }

    #[test]
    fn cases_json_lists_every_fixture_in_the_directory() {
        let mut listed: Vec<String> =
            cases().iter().map(|c| c["file"].as_str().unwrap_or("").to_string()).collect();
        listed.sort();
        let mut found: Vec<String> = std::fs::read_dir(dir())
            .expect("model-sets dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n != "cases.json")
            .collect();
        found.sort();
        assert_eq!(listed, found);
    }

    fn valid_doc() -> Value {
        let raw = std::fs::read(dir().join("valid-voice.json")).expect("valid-voice.json");
        serde_json::from_slice(&raw).expect("JSON")
    }

    fn code_of(v: &Value) -> &'static str {
        match validate(v.to_string().as_bytes()) {
            Ok(()) => "ok",
            Err(r) => r.code,
        }
    }

    #[test]
    fn a_null_anywhere_is_field_type_and_a_repeated_key_is_duplicate_key() {
        let mut v = valid_doc();
        assert_eq!(code_of(&v), "ok");
        v["license"]["url"] = Value::Null;
        assert_eq!(code_of(&v), "field_type");
        let dup = br#"["x"]"#;
        assert_eq!(validate(dup).expect_err("array").code, "field_type");
        let bytes = std::fs::read(dir().join("valid-voice.json")).unwrap();
        let raw = String::from_utf8(bytes).unwrap();
        let cut = raw.replacen("\"id\"", "\"id\": \"a\",\n  \"id\"", 1);
        assert_eq!(validate(cut.as_bytes()).expect_err("dup").code, "duplicate_key");
        assert_eq!(validate(b"").expect_err("empty").code, "bad_json");
    }

    #[test]
    fn a_bare_value_in_the_wrong_place_is_refused_with_its_own_code() {
        let mut v = valid_doc();
        v["files"][0]["bytes"] = Value::from(1.5);
        assert_eq!(code_of(&v), "field_type");
        let mut v = valid_doc();
        v["files"][0]["bytes"] = Value::from(0);
        assert_eq!(code_of(&v), "files_invalid");
    }

    fn archive_doc() -> Value {
        let raw = std::fs::read(dir().join("valid-from-archive.json")).expect("fixture");
        serde_json::from_slice(&raw).expect("JSON")
    }

    #[test]
    fn from_archive_is_judged_with_the_go_validators_codes() {
        let v = archive_doc();
        assert_eq!(code_of(&v), "ok");
        // A shape error inside from_archive.
        let mut v = archive_doc();
        v["files"][0]["from_archive"]["extra"] = Value::from(1);
        assert_eq!(code_of(&v), "unknown_field");
        let mut v = archive_doc();
        v["files"][0]["from_archive"]["bytes"] = Value::from("99");
        assert_eq!(code_of(&v), "field_type");
        let mut v = archive_doc();
        v["files"][0]["from_archive"].as_object_mut().unwrap().remove("sha256");
        assert_eq!(code_of(&v), "field_missing");
        // A bad value is from_archive_invalid, whichever of the three it is.
        let bad: [(&str, Value); 5] = [
            ("path", Value::from("../voices.tgz")),
            ("path", Value::from("a/b/c.tgz")),
            ("sha256", Value::from("7".repeat(63))),
            ("bytes", Value::from(0)),
            ("bytes", Value::from((1i64 << 40) + 1)),
        ];
        for (key, val) in bad {
            let mut v = archive_doc();
            v["files"][0]["from_archive"][key] = val.clone();
            assert_eq!(code_of(&v), "from_archive_invalid", "{key} = {val}");
        }
        // A notice file is staged as itself, never extracted.
        let mut v = archive_doc();
        v["files"][3]["from_archive"] = v["files"][0]["from_archive"].clone();
        assert_eq!(code_of(&v), "from_archive_invalid");
        // An earlier check still wins over from_archive (the Go order).
        let mut v = archive_doc();
        v["files"][0]["from_archive"]["bytes"] = Value::from(0);
        v["files"][0]["sha256"] = Value::from("nope");
        assert_eq!(code_of(&v), "sha256_invalid");
    }

    #[test]
    fn a_license_additional_notice_path_must_name_a_role_notice_file() {
        let mut v = archive_doc();
        v["license"]["additional"][0]["notice_path"] = Value::from("README.md");
        assert_eq!(code_of(&v), "ok");
        // Nothing is inferred: with no notice_path the entry stands alone.
        let mut v = archive_doc();
        v["license"]["additional"][0].as_object_mut().unwrap().remove("notice_path");
        assert_eq!(code_of(&v), "ok");
        // Not in files, in files but not a notice, and not a set path.
        for (path, want) in [
            ("absent.txt", "notice_not_in_files"),
            ("config.json", "notice_not_in_files"),
            ("model.safetensors", "notice_not_in_files"),
            ("../LICENSE.txt", "path_invalid"),
        ] {
            let mut v = archive_doc();
            v["license"]["additional"][0]["notice_path"] = Value::from(path);
            assert_eq!(code_of(&v), want, "{path}");
        }
        let mut v = archive_doc();
        v["license"]["additional"][0]["notice_path"] = Value::from(7);
        assert_eq!(code_of(&v), "field_type");
    }

    #[test]
    fn rfc3339_wants_a_real_calendar_time() {
        assert!(rfc3339("2026-11-05T10:20:30Z"));
        assert!(rfc3339("2026-11-05T10:20:30.125+01:00"));
        assert!(rfc3339("2028-02-29T00:00:00Z"));
        assert!(!rfc3339("2026-02-29T00:00:00Z"));
        assert!(!rfc3339("2026-13-05T10:20:30Z"));
        assert!(!rfc3339("2026-11-05 10:20:30Z"));
        assert!(!rfc3339("2026-11-05T10:20:30"));
        assert!(!rfc3339("2026-11-05T10:20:30.Z"));
        assert!(!rfc3339("unknown-time"));
    }

    #[test]
    fn the_path_rule_is_one_level_and_the_charset() {
        for ok in ["a.bin", "voices/a.bin", "README.md", "a-b_c.1"] {
            assert!(valid_set_path(ok), "{ok}");
        }
        let bad_ones = [
            "", "/a", "a/", "a//b", "a/b/c", "..", "../a", "a/..", "./a", "a b", "a\u{e9}",
        ];
        for bad in bad_ones {
            assert!(!valid_set_path(bad), "{bad:?}");
        }
    }
}
