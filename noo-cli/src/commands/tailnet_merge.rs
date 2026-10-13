// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Additive tailnet policy merge: make sure what noomesh DECLARES is present
//! in a live policy, and change nothing else.
//!
//! `noo security tailnet policy --push` is wholesale, and deliberately so: on a
//! tailnet that exists for noomesh, the declaration is the authority. But a
//! tailnet is often not noomesh's. An operator who already runs one has
//! grants for their own devices, their own tags and their own `ssh` rules,
//! and a wholesale push deletes all of them. Onboarding could therefore never
//! push, so it declared the TAGS a join key needs (`ensure_tag_owner`) and
//! stopped. The port GRANTS those tags exist for were never written; the
//! controller's `:8083` cache port was silently unreachable from every node
//! until someone added its grant by hand.
//!
//! This is the missing middle: an operator's policy plus exactly what noomesh
//! needs from it. Nothing is removed, reordered or rewritten. Anything this
//! file does not know how to add is refused out loud rather than skipped, so
//! a new section in the declaration cannot quietly fail to arrive.
//!
//! The one thing not preserved is the live policy's comments: the result is
//! posted as JSON. The admin console strips comments on every save, so a
//! console-managed policy has none to lose, and `push_acl` writes the full
//! live text to a backup before anything is posted.

use serde_json::{Map, Value};

/// The top-level sections the merge knows how to add. A declared section
/// outside this list is an error, not a skip.
const MERGEABLE: &[&str] = &["tagOwners", "acls"];

/// What an additive merge would add. Never anything removed — there is no
/// field for it, which is the point.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct MergePlan {
    /// Tags absent from the live `tagOwners`, added with their declared owners.
    pub tags_added: Vec<String>,
    /// `(tag, owner)` pairs added to a tag the live policy already had.
    pub owners_added: Vec<(String, String)>,
    /// Declared ACL entries with no identical entry live, as `src → dst`.
    pub acls_added: Vec<String>,
}

impl MergePlan {
    pub fn is_empty(&self) -> bool {
        self.tags_added.is_empty() && self.owners_added.is_empty() && self.acls_added.is_empty()
    }
}

/// HuJSON — JSON with `//` and `/* */` comments and trailing commas — to
/// strict JSON.
///
/// Unlike `tailnet_policy::strip_comments`, which is written for OUR file's
/// shape, this reads an operator's policy, which may hold a URL in a string,
/// a block comment, or an escaped quote. So it tracks string state
/// character by character: `//` inside a string is data.
pub(crate) fn hujson_to_json(src: &str) -> String {
    // Pass 1: comments out, strings intact.
    let chars: Vec<char> = src.chars().collect();
    let mut no_comments = String::with_capacity(src.len());
    let (mut i, mut in_str) = (0, false);
    while i < chars.len() {
        let c = chars[i];
        if in_str {
            no_comments.push(c);
            if c == '\\' && i + 1 < chars.len() {
                no_comments.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match (c, chars.get(i + 1)) {
            ('"', _) => {
                in_str = true;
                no_comments.push(c);
                i += 1;
            }
            ('/', Some('/')) => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            ('/', Some('*')) => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
            }
            _ => {
                no_comments.push(c);
                i += 1;
            }
        }
    }
    // Pass 2: a comma whose next non-space character closes a container.
    let chars: Vec<char> = no_comments.chars().collect();
    let mut out = String::with_capacity(no_comments.len());
    let (mut i, mut in_str) = (0, false);
    while i < chars.len() {
        let c = chars[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
        }
        if c == ',' {
            let next = chars[i + 1..].iter().find(|ch| !ch.is_whitespace());
            if matches!(next, Some('}') | Some(']')) {
                i += 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// A policy parsed from HuJSON.
pub(crate) fn parse_policy(hujson: &str) -> Result<Value, String> {
    let v: Value = serde_json::from_str(&hujson_to_json(hujson))
        .map_err(|e| format!("the policy is not valid HuJSON: {e}"))?;
    if !v.is_object() {
        return Err("the policy's top level is not an object".into());
    }
    Ok(v)
}

/// `(action, sorted src, sorted dst)` — two entries granting the same thing
/// are the same entry however their lists are ordered.
fn acl_key(entry: &Value) -> Option<(String, Vec<String>, Vec<String>)> {
    let list = |k: &str| -> Option<Vec<String>> {
        let mut v: Vec<String> = entry.get(k)?.as_array()?.iter().filter_map(|s| s.as_str().map(str::to_string)).collect();
        v.sort();
        Some(v)
    };
    let action = entry.get("action").and_then(Value::as_str).unwrap_or("accept").to_string();
    Some((action, list("src")?, list("dst")?))
}

/// `live` plus whatever of `declared` it lacks. Nothing is ever removed.
pub(crate) fn merge_additive(live: &Value, declared: &Value) -> Result<(Value, MergePlan), String> {
    let declared_obj = declared.as_object().ok_or("the declared policy is not an object")?;
    for key in declared_obj.keys() {
        if !MERGEABLE.contains(&key.as_str()) {
            return Err(format!(
                "the declared policy has a `{key}` section the additive merge does not know how to add. \
                 Teach tailnet_merge.rs to merge it rather than skipping it: an unmerged section is a \
                 grant that silently never arrives."
            ));
        }
    }
    let mut merged = live.clone();
    let merged_obj = merged.as_object_mut().ok_or("the live policy is not an object")?;
    let mut plan = MergePlan::default();

    if let Some(decl_owners) = declared_obj.get("tagOwners").and_then(Value::as_object) {
        let live_owners = merged_obj
            .entry("tagOwners")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or("the live `tagOwners` is not an object")?;
        for (tag, owners) in decl_owners {
            match live_owners.get_mut(tag) {
                None => {
                    live_owners.insert(tag.clone(), owners.clone());
                    plan.tags_added.push(tag.clone());
                }
                Some(have) => {
                    let have = have.as_array_mut().ok_or(format!("the live owners of {tag} are not a list"))?;
                    for o in owners.as_array().into_iter().flatten() {
                        if !have.contains(o) {
                            have.push(o.clone());
                            plan.owners_added.push((tag.clone(), o.as_str().unwrap_or_default().to_string()));
                        }
                    }
                }
            }
        }
    }

    if let Some(decl_acls) = declared_obj.get("acls").and_then(Value::as_array) {
        let live_acls = merged_obj
            .entry("acls")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or("the live `acls` is not a list")?;
        for entry in decl_acls {
            let key = acl_key(entry).ok_or("a declared ACL entry has no src/dst list")?;
            if !live_acls.iter().filter_map(acl_key).any(|k| k == key) {
                live_acls.push(entry.clone());
                plan.acls_added.push(format!("{} → {}", key.1.join(", "), key.2.join(", ")));
            }
        }
    }
    Ok((merged, plan))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hujson_keeps_urls_in_strings_and_drops_real_comments() {
        let src = r#"{
            // a line comment
            "hosts": {"docs": "https://example.com/a//b"}, /* a block
               comment */
            "note": "say \"hi\" // not a comment",
            "list": [1, 2,],
        }"#;
        let v: Value = serde_json::from_str(&hujson_to_json(src)).expect("valid JSON");
        assert_eq!(v["hosts"]["docs"], "https://example.com/a//b", "a // inside a string is data");
        assert_eq!(v["note"], "say \"hi\" // not a comment", "escaped quotes do not end the string");
        assert_eq!(v["list"], json!([1, 2]), "trailing commas are dropped");
    }

    fn declared() -> Value {
        json!({
            "tagOwners": {
                "tag:controller": ["autogroup:admin"],
                "tag:worker": ["autogroup:admin", "tag:controller"],
            },
            "acls": [
                {"action": "accept", "src": ["tag:worker"], "dst": ["tag:controller:8080,4222,8443"]},
                {"action": "accept", "src": ["autogroup:member"], "dst": ["tag:controller:443"]},
            ],
        })
    }

    /// An earlier change widened the worker grant with :8443 (the model
    /// cache's mTLS listener). A tailnet that holds the pre-8443 grant must
    /// GAIN the port: the merge keys on the whole entry, so the widened
    /// grant is appended and the narrower one is left where it was (nothing
    /// is ever removed). Without this the roll would leave every node's
    /// preseed timing out on a port the policy never opened — the :8083
    /// failure, repeated.
    #[test]
    fn a_widened_grant_reaches_a_tailnet_holding_the_old_one() {
        let mut live = declared();
        live["acls"][0]["dst"] = json!(["tag:controller:8080", "tag:controller:4222"]);
        let (merged, plan) = merge_additive(&live, &declared()).unwrap();
        assert_eq!(plan.acls_added, vec!["tag:worker → tag:controller:8080,4222,8443"]);
        let acls = merged["acls"].as_array().unwrap();
        assert_eq!(acls.len(), 3, "the old grant is kept, the widened one appended");
        assert!(acls.iter().any(|a| a["dst"].as_array().unwrap().iter().any(|d| d.as_str().unwrap().contains("8443"))));
    }

    /// The case the user asked for: an operator's own tailnet. Everything
    /// of theirs survives untouched; noomesh's grants are appended.
    #[test]
    fn an_operators_own_rules_survive_and_ours_are_added() {
        let live = json!({
            "groups": {"group:family": ["me@example.com"]},
            "tagOwners": {"tag:nas": ["autogroup:admin"]},
            "acls": [{"action": "accept", "src": ["group:family"], "dst": ["tag:nas:*"]}],
            "ssh": [{"action": "check", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"]}],
        });
        let (merged, plan) = merge_additive(&live, &declared()).unwrap();
        // theirs, untouched
        assert_eq!(merged["groups"], live["groups"]);
        assert_eq!(merged["ssh"], live["ssh"]);
        assert_eq!(merged["tagOwners"]["tag:nas"], json!(["autogroup:admin"]));
        assert_eq!(merged["acls"][0], live["acls"][0], "their grant stays first and unchanged");
        // ours, added
        assert_eq!(plan.tags_added, vec!["tag:controller", "tag:worker"]);
        assert_eq!(plan.acls_added.len(), 2);
        assert_eq!(merged["acls"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn a_policy_that_already_has_everything_is_left_alone() {
        let (merged, plan) = merge_additive(&declared(), &declared()).unwrap();
        assert!(plan.is_empty(), "{plan:?}");
        assert_eq!(merged, declared());
    }

    /// Same grant, lists in a different order: already present, not a
    /// duplicate to append.
    #[test]
    fn list_order_does_not_make_a_grant_new() {
        let mut live = declared();
        live["acls"][0]["dst"] = json!(["tag:controller:8080,4222,8443"]);
        live["acls"][1] = json!({"src": ["autogroup:member"], "dst": ["tag:controller:443"]}); // action omitted = accept
        let (_, plan) = merge_additive(&live, &declared()).unwrap();
        assert!(plan.acls_added.is_empty(), "{:?}", plan.acls_added);
    }

    /// The :8083 shape: the tags exist (ensure_tag_owner put them there) but
    /// a port grant never did.
    #[test]
    fn a_missing_grant_is_added_when_the_tags_already_exist() {
        let mut live = declared();
        live["acls"].as_array_mut().unwrap().remove(0);
        let (merged, plan) = merge_additive(&live, &declared()).unwrap();
        assert!(plan.tags_added.is_empty() && plan.owners_added.is_empty());
        assert_eq!(plan.acls_added, vec!["tag:worker → tag:controller:8080,4222,8443"]);
        assert_eq!(merged["acls"].as_array().unwrap().len(), 2);
    }

    /// A tag the operator already owns keeps its owners; ours are added
    /// beside them. tag:controller as co-owner of tag:worker is load-bearing
    /// (an OAuth client can only mint keys for tags its own tags own).
    #[test]
    fn missing_owners_are_added_and_existing_ones_kept() {
        let mut live = declared();
        live["tagOwners"]["tag:worker"] = json!(["group:ops"]);
        let (merged, plan) = merge_additive(&live, &declared()).unwrap();
        assert_eq!(merged["tagOwners"]["tag:worker"], json!(["group:ops", "autogroup:admin", "tag:controller"]));
        assert_eq!(plan.owners_added.len(), 2);
    }

    /// Nothing is ever removed, whatever the live policy holds.
    #[test]
    fn nothing_is_ever_removed() {
        let live = json!({"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}], "tagOwners": {"tag:x": ["a"]}});
        let (merged, _) = merge_additive(&live, &declared()).unwrap();
        assert_eq!(merged["acls"][0], live["acls"][0]);
        assert_eq!(merged["tagOwners"]["tag:x"], json!(["a"]));
    }

    /// A section the merge cannot add is refused, not skipped.
    #[test]
    fn an_unknown_declared_section_is_refused_out_loud() {
        let mut d = declared();
        d["ssh"] = json!([]);
        let err = merge_additive(&json!({}), &d).unwrap_err();
        assert!(err.contains("`ssh`"), "{err}");
    }

    /// The declaration this binary ships must merge: if it gains a section
    /// the merge can't handle, this fails at build time rather than on an
    /// operator's first onboard.
    #[test]
    fn the_shipped_declaration_merges_into_an_empty_tailnet() {
        let Some(p) = crate::commands::tailnet_policy::declared_policy() else { return };
        let decl = parse_policy(p).expect("the declared policy parses as HuJSON");
        let (_, plan) = merge_additive(&json!({}), &decl).expect("the declared policy merges");
        assert!(!plan.tags_added.is_empty() && !plan.acls_added.is_empty(), "{plan:?}");
    }
}
