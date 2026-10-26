// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `config/harness-profiles.json`, as the CLI reads it: the harness profile
//! field names `noo cluster profile <node> --set` may name, each field's
//! value type (read off the tier rows, so a new field is one edit to that
//! file), and the tier defaults for display.
//!
//! The gateway (`gateway-rust/src/harness_profile.rs`) owns the resolution
//! (override > measured > tier default) and the validation; the CLI only
//! turns `key=value` text into the JSON value the gateway judges.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{json, Map, Value};

/// The shipped table, embedded at build time like the gateway's copy.
pub const HARNESS_PROFILES_JSON: &str = include_str!("../../config/harness-profiles.json");

#[derive(Debug, Clone, Deserialize)]
pub struct Table {
    /// The fields, in declared order.
    pub fields: Vec<String>,
    /// Tier number → that tier's defaults.
    pub tiers: BTreeMap<String, Map<String, Value>>,
    /// The tier a node with no (or an unlisted) tier resolves as.
    pub unknown_tier: String,
    /// The measured rule: `reference_prompt_tokens`, `headroom`,
    /// `max_first_byte_secs` (for the explanation `--bench` prints).
    #[serde(default)]
    pub measured: Map<String, Value>,
}

/// Parse a table (the shipped one, or a test fixture).
pub fn parse(raw: &str) -> Result<Table, String> {
    serde_json::from_str(raw).map_err(|e| format!("config/harness-profiles.json does not parse: {e}"))
}

/// The shipped table. Built in, so a parse failure is a build-time defect
/// the tests below catch; at run time it reads as an empty table.
pub fn shipped() -> Table {
    parse(HARNESS_PROFILES_JSON).unwrap_or(Table { fields: Vec::new(), tiers: BTreeMap::new(), unknown_tier: String::new(), measured: Map::new() })
}

/// `context`'s name until 0.6.13 (i226 decision 1): accepted on `--set` and
/// `--clear` for one release and read from a gateway that still sends it.
pub const CONTEXT_ALIAS: &str = "ollama_context";

/// The table's name for `key`: [`CONTEXT_ALIAS`] is `context`.
pub fn canonical(key: &str) -> &str {
    if key == CONTEXT_ALIAS { "context" } else { key }
}

impl Table {
    /// A tier row to read value types from: the unknown tier's, else any.
    fn exemplar(&self) -> Option<&Map<String, Value>> {
        self.tiers.get(&self.unknown_tier).or_else(|| self.tiers.values().next())
    }

    /// `key=value` text → `(key, JSON value)`, typed by the tier rows: a
    /// number field takes a whole number, a list field takes
    /// comma-separated names (`none` for an empty list), a word field the
    /// word. The gateway judges the value itself (ranges, allowed words,
    /// allowed kinds).
    pub fn parse_assignment(&self, kv: &str) -> Result<(String, Value), String> {
        let (key, raw) = kv
            .split_once('=')
            .ok_or_else(|| format!("'{kv}' is not key=value (fields: {})", self.fields.join(", ")))?;
        let key = canonical(key.trim());
        self.check_field(key)?;
        let raw = raw.trim();
        let kind = self.exemplar().and_then(|r| r.get(key)).cloned().unwrap_or(Value::Null);
        let value = match kind {
            Value::Number(_) => {
                json!(raw.parse::<u64>().map_err(|_| format!("{key} takes a whole number, not '{raw}'"))?)
            }
            Value::Array(_) => {
                if raw.is_empty() || raw == "none" {
                    json!([])
                } else {
                    json!(raw.split(',').map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>())
                }
            }
            _ => {
                if raw.is_empty() {
                    return Err(format!("{key} needs a value (`--clear {key}` removes the override)"));
                }
                json!(raw)
            }
        };
        Ok((key.to_string(), value))
    }

    /// Is `key` one of the table's fields?
    pub fn check_field(&self, key: &str) -> Result<(), String> {
        let key = canonical(key);
        if self.fields.iter().any(|f| f == key) {
            Ok(())
        } else {
            Err(format!("'{key}' is not a harness profile field (one of {})", self.fields.join(", ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_table_parses_with_six_fields_and_four_tiers() {
        let t = parse(HARNESS_PROFILES_JSON).expect("shipped table");
        assert_eq!(t.fields, ["first_byte_secs", "stream_idle_secs", "thinking", "context", "claude_prompt", "foreign_kinds"]);
        assert_eq!(t.tiers.keys().cloned().collect::<Vec<_>>(), ["1", "2", "3", "4"]);
        assert!(t.tiers.contains_key(&t.unknown_tier));
    }

    #[test]
    fn assignments_are_typed_by_the_table() {
        let t = shipped();
        assert_eq!(t.parse_assignment("first_byte_secs=900").unwrap(), ("first_byte_secs".into(), json!(900)));
        assert_eq!(t.parse_assignment(" thinking = on ").unwrap(), ("thinking".into(), json!("on")));
        assert_eq!(t.parse_assignment("foreign_kinds=codex, copilot").unwrap(), ("foreign_kinds".into(), json!(["codex", "copilot"])));
        assert_eq!(t.parse_assignment("foreign_kinds=none").unwrap(), ("foreign_kinds".into(), json!([])));
        assert!(t.parse_assignment("first_byte_secs=soon").unwrap_err().contains("whole number"));
        assert!(t.parse_assignment("first_byte_secs").unwrap_err().contains("key=value"));
        assert!(t.parse_assignment("bogus=1").unwrap_err().contains("not a harness profile field"));
        assert!(t.parse_assignment("thinking=").unwrap_err().contains("--clear thinking"));
        // The old name (i226 decision 1) is the new field.
        assert_eq!(t.parse_assignment("context=65536").unwrap(), ("context".into(), json!(65536)));
        assert_eq!(t.parse_assignment("ollama_context=65536").unwrap(), ("context".into(), json!(65536)));
        assert!(t.check_field("ollama_context").is_ok());
    }
}
