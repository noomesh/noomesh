// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `Measured<T>` — one type for a status field the gateway may be unable to
//! measure (PATTERNS_TO_APPLY #1, "tri-state status end to end").
//!
//! A number, flag or string the gateway cannot take is `null` on the wire with
//! a sibling `<field>_detail` sentence saying why — never a literal 0, never a
//! parallel `error` string next to a zero. The `noo` CLI renders the null with
//! `ui::count` ("not reported"), the console with `lib/num.ts` (a dash).
//!
//! Wire shape, which the routes that predate this type already served:
//!   - value present, no note : `"name": v`                       (no detail key)
//!   - value absent           : `"name": null, "name_detail": why`
//!   - value present WITH note: `"name": v, "name_detail": note`  (scope notes,
//!     loop-liveness sentences: the detail rides along with a real answer)
//!   - [`put_keyed`] additionally pins the detail key to `null` when there is
//!     nothing to say, and names it freely (`history_entries` / `history_detail`),
//!     for the routes whose readers already look the key up unconditionally.
//!
//! A failure is never written into a detail verbatim: [`Measured::from_result`]
//! logs the error under a short ref and the detail carries only the ref, so SQL
//! text, hostnames and paths do not leave in a response (same rule as
//! `routes::internal_response`).

use serde::Serialize;
use serde_json::{Map, Value};

/// A measurement a status route may be unable to take.
#[derive(Debug, Clone, PartialEq)]
pub struct Measured<T> {
    pub value: Option<T>,
    pub detail: Option<String>,
}

impl<T> Measured<T> {
    /// Measured, nothing to add.
    pub fn of(v: T) -> Self {
        Self { value: Some(v), detail: None }
    }

    /// Not measurable: serialises as `null` plus `why`.
    pub fn unmeasured(why: impl Into<String>) -> Self {
        Self { value: None, detail: Some(why.into()) }
    }

    /// An answer that always travels with a sentence (loop liveness, scope
    /// notes): `value` may be present or absent, `detail` is always emitted.
    pub fn noted(value: Option<T>, detail: impl Into<String>) -> Self {
        Self { value, detail: Some(detail.into()) }
    }

    /// Measured when `r` is Ok. On Err the error is logged under a short ref
    /// and the detail says only "not measured (ref …)" — never the error text.
    pub fn from_result<E: std::fmt::Display>(r: Result<T, E>) -> Self {
        match r {
            Ok(v) => Self::of(v),
            Err(e) => Self::unmeasured(not_measured(&e)),
        }
    }

    /// Like [`Measured::from_result`] but with a lead-in that names what could
    /// not be read: `"unknown — <what> (ref …)"` style detail.
    pub fn from_result_in<E: std::fmt::Display>(r: Result<T, E>, what: &str) -> Self {
        match r {
            Ok(v) => Self::of(v),
            Err(e) => Self::unmeasured(not_measured_in(what, &e)),
        }
    }
}

/// Log `e` under a fresh ref and return `(ref xxxxxxxx)` for a detail sentence
/// to embed; the error text itself never leaves the process.
pub fn ref_note<E: std::fmt::Display>(e: &E) -> String {
    let r = crate::routes::short_ref();
    tracing::warn!(ref_id = %r, error = %e, "status field not measured");
    format!("(ref {r})")
}

/// Log `e` under a fresh ref and return the response-safe detail.
pub fn not_measured<E: std::fmt::Display>(e: &E) -> String {
    format!("not measured {}; the gateway log has the cause", ref_note(e))
}

/// As [`not_measured`], prefixed with what could not be read.
pub fn not_measured_in<E: std::fmt::Display>(what: &str, e: &E) -> String {
    format!("unknown — {what} {}; the gateway log has the cause", ref_note(e))
}

fn value_of<T: Serialize>(v: &Option<T>) -> Value {
    match v {
        Some(v) => serde_json::to_value(v).unwrap_or(Value::Null),
        None => Value::Null,
    }
}

/// Insert `name` and, when there is a detail, `name_detail`.
pub fn put<T: Serialize>(map: &mut Map<String, Value>, name: &str, m: Measured<T>) {
    map.insert(name.to_string(), value_of(&m.value));
    if let Some(d) = m.detail {
        map.insert(format!("{name}_detail"), Value::String(d));
    }
}

/// Insert `name` and ALWAYS `detail_key` (null when there is nothing to say).
pub fn put_keyed<T: Serialize>(map: &mut Map<String, Value>, name: &str, detail_key: &str, m: Measured<T>) {
    map.insert(name.to_string(), value_of(&m.value));
    map.insert(detail_key.to_string(), m.detail.map(Value::String).unwrap_or(Value::Null));
}

/// [`put`] onto a `json!({...})` object; a no-op if `body` is not an object.
pub fn put_into<T: Serialize>(body: &mut Value, name: &str, m: Measured<T>) {
    if let Some(map) = body.as_object_mut() {
        put(map, name, m);
    }
}

/// [`put_keyed`] onto a `json!({...})` object.
pub fn put_keyed_into<T: Serialize>(body: &mut Value, name: &str, detail_key: &str, m: Measured<T>) {
    if let Some(map) = body.as_object_mut() {
        put_keyed(map, name, detail_key, m);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one<T: Serialize>(name: &str, m: Measured<T>) -> Value {
        let mut map = Map::new();
        put(&mut map, name, m);
        Value::Object(map)
    }

    #[test]
    fn a_measured_value_has_no_detail_key() {
        let v = one("count", Measured::of(7_i64));
        assert_eq!(v, serde_json::json!({"count": 7}));
        assert!(v.get("count_detail").is_none());
    }

    #[test]
    fn an_unmeasured_value_is_null_with_its_reason() {
        let v = one("count", Measured::<i64>::unmeasured("redis is not configured"));
        assert_eq!(v["count"], Value::Null);
        assert_eq!(v["count_detail"], "redis is not configured");
    }

    #[test]
    fn a_noted_answer_carries_both() {
        let v = one("running", Measured::noted(Some(true), "loop ticked 3s ago"));
        assert_eq!(v, serde_json::json!({"running": true, "running_detail": "loop ticked 3s ago"}));
        let v = one("running", Measured::<bool>::noted(None, "never ticked"));
        assert_eq!(v, serde_json::json!({"running": null, "running_detail": "never ticked"}));
    }

    #[test]
    fn put_keyed_pins_the_detail_key_even_when_measured() {
        let mut map = Map::new();
        put_keyed(&mut map, "history_entries", "history_detail", Measured::of(3_i64));
        assert_eq!(Value::Object(map), serde_json::json!({"history_entries": 3, "history_detail": null}));
        let mut map = Map::new();
        put_keyed(&mut map, "history_entries", "history_detail", Measured::<i64>::unmeasured("gone"));
        assert_eq!(Value::Object(map), serde_json::json!({"history_entries": null, "history_detail": "gone"}));
    }

    #[test]
    fn put_into_ignores_a_non_object() {
        let mut v = serde_json::json!([1]);
        put_into(&mut v, "x", Measured::of(1));
        assert_eq!(v, serde_json::json!([1]));
    }

    #[test]
    fn a_failure_detail_carries_a_ref_and_never_the_error_text() {
        let nasty = "Database error: relation \"noo_x\" does not exist at /var/lib/postgresql/data (SELECT COUNT(*) FROM noo_x)";
        let m = Measured::<i64>::from_result(Err::<i64, _>(nasty));
        let d = m.detail.expect("detail");
        assert!(m.value.is_none());
        assert!(d.starts_with("not measured (ref "), "{d}");
        for leak in ["Database error", "SELECT", "/var/lib", "noo_x"] {
            assert!(!d.contains(leak), "{leak} leaked: {d}");
        }
        let d = Measured::<i64>::from_result_in(Err::<i64, _>(nasty), "the audit store")
            .detail
            .unwrap();
        assert!(d.contains("the audit store") && d.contains("ref "), "{d}");
        assert!(!d.contains("SELECT") && !d.contains("/var/lib"), "{d}");
    }

    #[test]
    fn from_result_ok_is_measured() {
        assert_eq!(Measured::from_result(Ok::<_, String>(4)), Measured::of(4));
    }
}
