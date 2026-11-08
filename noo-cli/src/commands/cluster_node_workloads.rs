// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster workloads place|show|unplace` — the operator's placement of an
//! add-on's node workload on ONE node (i573), over the gateway routes in
//! `gateway-rust/src/routes/node_workload_placements.rs`:
//!
//! ```text
//! PUT    /api/cluster/nodes/<node>/node-workloads/<addon>/<workload>
//! DELETE /api/cluster/nodes/<node>/node-workloads/<addon>/<workload>
//! GET    /api/cluster/nodes/<node>/node-workloads
//! ```
//!
//! The gateway validates everything (sets, profile, env, consent, the node's
//! hard filters); this file only builds the request from the arguments and
//! renders the answer. Parsing, body building and formatting are pure
//! functions so the tests need no gateway. Every path segment is
//! percent-encoded, and `.`/`..`/empty segments are refused locally, so a
//! node or add-on name can never add or remove a path segment.
//!
//! Bare `noo cluster workloads` (the list of what add-ons declare) stays in
//! `cluster_reserve.rs`; only the words place/show/unplace reach this file.

use serde_json::{json, Map, Value};

use crate::args::{ArgError, Args};
use crate::http::request_status;
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col};
use crate::{Globals, Unhandled};

/// One `--set <slot>=<id>@<rev>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetArg {
    pub slot: String,
    pub id: String,
    pub revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlaceArgs {
    pub node: String,
    pub addon: String,
    pub workload: String,
    pub profile: Option<String>,
    pub sets: Vec<SetArg>,
    pub env: Vec<(String, String)>,
    pub on_controller: bool,
}

/// A path segment the gateway route would take as one name.
fn check_segment(what: &str, s: &str) -> Result<(), ArgError> {
    if s.is_empty() || s == "." || s == ".." {
        return Err(ArgError::new(format!("{what} `{s}` is not a usable name")));
    }
    Ok(())
}

/// `<addon>/<workload>`: exactly one `/`, both sides non-empty.
pub(crate) fn parse_workload_ref(raw: &str) -> Result<(String, String), ArgError> {
    let bad = || ArgError::new(format!("`{raw}` is not <addon>/<workload>"));
    if raw.matches('/').count() != 1 {
        return Err(bad());
    }
    let (addon, workload) = raw.split_once('/').ok_or_else(bad)?;
    if addon.is_empty() || workload.is_empty() {
        return Err(bad());
    }
    check_segment("add-on", addon)?;
    check_segment("workload", workload)?;
    Ok((addon.to_string(), workload.to_string()))
}

/// `<slot>=<id>@<rev>`: slot up to the first `=`, id up to the LAST `@`.
pub(crate) fn parse_set(raw: &str) -> Result<SetArg, ArgError> {
    let bad = || ArgError::new(format!("--set `{raw}` is not <slot>=<id>@<rev>"));
    let (slot, rest) = raw.split_once('=').ok_or_else(bad)?;
    let (id, revision) = rest.rsplit_once('@').ok_or_else(bad)?;
    if slot.is_empty() || id.is_empty() || revision.is_empty() {
        return Err(bad());
    }
    Ok(SetArg { slot: slot.to_string(), id: id.to_string(), revision: revision.to_string() })
}

/// `K=V`: split at the first `=`; an empty key is an error, an empty value is not.
pub(crate) fn parse_env(raw: &str) -> Result<(String, String), ArgError> {
    let Some((k, v)) = raw.split_once('=') else {
        return Err(ArgError::new(format!("--env `{raw}` is not K=V")));
    };
    if k.is_empty() {
        return Err(ArgError::new(format!("--env `{raw}` has an empty key")));
    }
    Ok((k.to_string(), v.to_string()))
}

pub(crate) fn parse_place(args: &[String]) -> Result<PlaceArgs, ArgError> {
    parse_place_with(&mut Args::new(args))
}

pub(crate) fn parse_place_with(a: &mut Args) -> Result<PlaceArgs, ArgError> {
    let profile = a.value(&["--profile"])?.map(|s| s.trim().to_string());
    if profile.as_deref() == Some("") {
        return Err(ArgError::new("--profile needs a name"));
    }
    let raw_sets = a.values(&["--set"])?;
    let raw_env = a.values(&["--env"])?;
    let on_controller = a.flag(&["--on-controller"]);
    let pos = a.positionals()?;
    let [node, workload_ref] = pos.as_slice() else {
        return Err(ArgError::new("expected <node> <addon>/<workload>"));
    };
    check_segment("node", node)?;
    let (addon, workload) = parse_workload_ref(workload_ref)?;
    let mut sets = Vec::new();
    for raw in &raw_sets {
        sets.push(parse_set(raw)?);
    }
    let mut env: Vec<(String, String)> = Vec::new();
    for raw in &raw_env {
        let (k, v) = parse_env(raw)?;
        if env.iter().any(|(seen, _)| *seen == k) {
            return Err(ArgError::new(format!("--env `{k}` is given twice")));
        }
        env.push((k, v));
    }
    Ok(PlaceArgs { node: node.clone(), addon, workload, profile, sets, env, on_controller })
}

/// `show <node> [<addon>/<workload>]`
pub(crate) fn parse_show(args: &[String]) -> Result<(String, Option<(String, String)>), ArgError> {
    let pos = Args::new(args).positionals()?;
    match pos.as_slice() {
        [node] => {
            check_segment("node", node)?;
            Ok((node.clone(), None))
        }
        [node, wl] => {
            check_segment("node", node)?;
            Ok((node.clone(), Some(parse_workload_ref(wl)?)))
        }
        _ => Err(ArgError::new("expected <node> [<addon>/<workload>]")),
    }
}

/// `unplace <node> <addon>/<workload>`
pub(crate) fn parse_unplace(args: &[String]) -> Result<(String, String, String), ArgError> {
    let pos = Args::new(args).positionals()?;
    let [node, wl] = pos.as_slice() else {
        return Err(ArgError::new("expected <node> <addon>/<workload>"));
    };
    check_segment("node", node)?;
    let (addon, workload) = parse_workload_ref(wl)?;
    Ok((node.clone(), addon, workload))
}

/// The PUT body (the gateway's `PutBody`). A repeated slot appends.
pub(crate) fn place_body(p: &PlaceArgs) -> Value {
    let mut sets: Map<String, Value> = Map::new();
    for s in &p.sets {
        let slot = sets.entry(s.slot.clone()).or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(items) = slot {
            items.push(json!({"id": s.id, "revision": s.revision}));
        }
    }
    let mut env: Map<String, Value> = Map::new();
    for (k, v) in &p.env {
        env.insert(k.clone(), Value::String(v.clone()));
    }
    let mut body = json!({"sets": sets, "env": env, "on_controller": p.on_controller});
    if let Some(profile) = &p.profile {
        body["profile"] = Value::String(profile.clone());
    }
    body
}

fn encode(s: &str) -> String {
    super::urlencode(s)
}

/// The per-workload route, every segment percent-encoded.
pub(crate) fn placement_path(node: &str, addon: &str, workload: &str) -> String {
    format!("/api/cluster/nodes/{}/node-workloads/{}/{}", encode(node), encode(addon), encode(workload))
}

/// The per-node list route.
pub(crate) fn list_path(node: &str) -> String {
    format!("/api/cluster/nodes/{}/node-workloads", encode(node))
}

/// The gateway's `{"error": code, "detail": sentence}`; anything else keeps
/// its text and gets the status as the code.
pub(crate) fn parse_refusal(status: u16, text: &str) -> (String, String) {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        if let Some(code) = v["error"].as_str() {
            return (code.to_string(), v["detail"].as_str().unwrap_or("").to_string());
        }
    }
    (format!("http_{status}"), text.trim().to_string())
}

/// `refused (<code>): <detail>`
pub(crate) fn format_refusal(code: &str, detail: &str) -> String {
    if detail.is_empty() {
        format!("refused ({code})")
    } else {
        format!("refused ({code}): {detail}")
    }
}

/// The `sha256:<hex>` the gateway's detail names, if it does.
fn digest_in(detail: &str) -> Option<String> {
    let at = detail.find("sha256:")?;
    let hex: String = detail[at + "sha256:".len()..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if hex.is_empty() {
        None
    } else {
        Some(format!("sha256:{hex}"))
    }
}

/// For `consent_none` / `consent_unapproved` only: the approval happens on the
/// node itself. Plain prose (no backticks, not starting with the binary
/// name), because the node-side command lives in another branch and the hint
/// lint checks suggested commands against usage.rs.
pub(crate) fn approve_hint(code: &str, node: &str, addon: &str, detail: &str) -> Option<String> {
    if code != "consent_none" && code != "consent_unapproved" {
        return None;
    }
    let digest = digest_in(detail).unwrap_or_else(|| "<digest>".to_string());
    Some(format!("on {node}, run: noo node workloads approve {addon} {digest}"))
}

/// `sha256:` plus the first 12 hex digits.
pub(crate) fn short_digest(digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    let short: String = hex.chars().take(12).collect();
    format!("sha256:{short}")
}

pub(crate) fn format_placed(resp: &Value) -> String {
    format!(
        "{}/{}: placed on {} — {}, image {} {}",
        resp["addon"].as_str().unwrap_or("?"),
        resp["workload"].as_str().unwrap_or("?"),
        resp["node_id"].as_str().unwrap_or("?"),
        resp["state"].as_str().unwrap_or("?"),
        resp["image"]["name"].as_str().unwrap_or("?"),
        short_digest(resp["image"]["digest"].as_str().unwrap_or("?")),
    )
}

pub(crate) fn format_unplaced(resp: &Value) -> String {
    format!(
        "{}/{}: unplaced from {}",
        resp["addon"].as_str().unwrap_or("?"),
        resp["workload"].as_str().unwrap_or("?"),
        resp["node_id"].as_str().unwrap_or("?"),
    )
}

/// The GET list narrowed to the named workload, or all of it.
pub(crate) fn select_workloads(body: &Value, which: Option<(&str, &str)>) -> Vec<Value> {
    let empty = Vec::new();
    body["node_workloads"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter(|w| match which {
            None => true,
            Some((addon, workload)) => w["addon"].as_str() == Some(addon) && w["workload"].as_str() == Some(workload),
        })
        .cloned()
        .collect()
}

/// `main=id@rev,id@rev voices=id@rev`
pub(crate) fn sets_summary(sets: &Value) -> String {
    let Some(map) = sets.as_object() else { return "-".to_string() };
    let parts: Vec<String> = map
        .iter()
        .map(|(slot, items)| {
            let refs: Vec<String> = items
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|i| format!("{}@{}", i["id"].as_str().unwrap_or("?"), i["revision"].as_str().unwrap_or("?")))
                        .collect()
                })
                .unwrap_or_default();
            format!("{slot}={}", refs.join(","))
        })
        .collect();
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

/// One table row for a listed workload.
pub(crate) fn workload_row(w: &Value) -> Vec<String> {
    vec![
        format!("{}/{}", w["addon"].as_str().unwrap_or("?"), w["workload"].as_str().unwrap_or("?")),
        w["state"].as_str().unwrap_or("?").to_string(),
        w["profile"].as_str().filter(|p| !p.is_empty()).unwrap_or("-").to_string(),
        sets_summary(&w["sets"]),
        if w["on_controller"].as_bool().unwrap_or(false) { "yes".to_string() } else { "no".to_string() },
    ]
}

/// Render a refusal and exit: the gateway's code and sentence, plus the
/// approve hint where the node has to consent first.
fn refused(g: &Globals, what: &str, node: &str, addon: &str, status: u16, text: &str) -> ! {
    let (code, detail) = parse_refusal(status, text);
    let hint = approve_hint(&code, node, addon, &detail);
    fail(g.json, ExitCode::RemoteError, &code, &format!("{what}: {}", format_refusal(&code, &detail)), hint.as_deref())
}

/// `noo cluster workloads place <node> <addon>/<workload> [--profile <p>] [--set <slot>=<id>@<rev>]... [--env K=V]... [--on-controller]`
pub fn cluster_workloads_place(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let p = parse_place(args)?;
    let what = format!("{}/{}", p.addon, p.workload);
    let path = placement_path(&p.node, &p.addon, &p.workload);
    let body = place_body(&p);
    let resp = match request_status(g, "PUT", &path, Some(&body), true, 120) {
        Ok(v) => v,
        Err((status, text)) => refused(g, &what, &p.node, &p.addon, status, &text),
    };
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    ui::done(&format_placed(&resp));
    Ok(0)
}

/// `noo cluster workloads show <node> [<addon>/<workload>]`
pub fn cluster_workloads_show(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (node, which) = parse_show(args)?;
    let what = which.as_ref().map(|(a, w)| format!("{a}/{w}")).unwrap_or_else(|| node.clone());
    let addon = which.as_ref().map(|(a, _)| a.as_str()).unwrap_or("");
    let body = match request_status(g, "GET", &list_path(&node), None, true, 30) {
        Ok(v) => v,
        Err((status, text)) => refused(g, &what, &node, addon, status, &text),
    };
    let list = select_workloads(&body, which.as_ref().map(|(a, w)| (a.as_str(), w.as_str())));
    if list.is_empty() && which.is_some() {
        fail(g.json, ExitCode::RemoteError, "not_found", &format!("{what} is not placed on {node}"), None);
    }
    if g.json {
        println!("{}", json!({"node_id": node, "node_workloads": list}));
        return Ok(0);
    }
    println!("{}", ui::header(&format!("{node} workloads"), Some("placed add-on node workloads")));
    if list.is_empty() {
        println!("{}", ui::muted("none placed"));
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = list.iter().map(workload_row).collect();
    println!("{}", ui::table(&[Col::left("workload"), Col::left("state"), Col::left("profile"), Col::left("sets"), Col::left("controller")], &rows));
    if which.is_some() {
        for w in &list {
            if let Some(env) = w["env"].as_object() {
                for (k, v) in env {
                    println!("{}", ui::muted(&format!("env {k}={}", v.as_str().unwrap_or(""))));
                }
            }
        }
    }
    Ok(0)
}

/// `noo cluster workloads unplace <node> <addon>/<workload>`
pub fn cluster_workloads_unplace(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (node, addon, workload) = parse_unplace(args)?;
    let what = format!("{addon}/{workload}");
    let resp = match request_status(g, "DELETE", &placement_path(&node, &addon, &workload), None, true, 60) {
        Ok(v) => v,
        Err((status, text)) => refused(g, &what, &node, &addon, status, &text),
    };
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    ui::done(&format_unplaced(&resp));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    const REV: &str = "fdaf4090a61cb315c138a1faee287ffd6c716309";

    fn voice_args(extra: &[&str]) -> Vec<String> {
        let mut v = vec![
            "--profile", "int8",
            "--set", "main=personaplex-7b-v1@fdaf4090a61cb315c138a1faee287ffd6c716309",
            "--set", "voices=personaplex-voices@fdaf4090a61cb315c138a1faee287ffd6c716309",
            "--env", "PAI_VOICE_SLOTS=1",
            "--env", "PAI_VOICE_QUANTIZATION=int8",
            "--env", "PAI_VOICE_CPU_OFFLOAD=false",
        ];
        v.extend_from_slice(extra);
        v.extend_from_slice(&["awolf", "pai-voice/native-voice"]);
        a(&v)
    }

    #[test]
    fn place_builds_exactly_the_put_body_for_the_voice_placement() {
        let p = parse_place(&voice_args(&[])).expect("parses");
        assert_eq!((p.node.as_str(), p.addon.as_str(), p.workload.as_str()), ("awolf", "pai-voice", "native-voice"));
        assert_eq!(
            place_body(&p),
            json!({
                "profile": "int8",
                "sets": {
                    "main": [{"id": "personaplex-7b-v1", "revision": REV}],
                    "voices": [{"id": "personaplex-voices", "revision": REV}],
                },
                "env": {
                    "PAI_VOICE_SLOTS": "1",
                    "PAI_VOICE_QUANTIZATION": "int8",
                    "PAI_VOICE_CPU_OFFLOAD": "false",
                },
                "on_controller": false,
            })
        );
    }

    #[test]
    fn on_controller_flag_sets_the_body_field_true() {
        let p = parse_place(&voice_args(&["--on-controller"])).expect("parses");
        assert!(p.on_controller);
        assert_eq!(place_body(&p)["on_controller"], json!(true));
        let bare = parse_place(&a(&["awolf", "a/b"])).expect("parses");
        assert_eq!(place_body(&bare), json!({"sets": {}, "env": {}, "on_controller": false}));
    }

    #[test]
    fn a_repeated_set_on_one_slot_appends_in_order() {
        let p = parse_place(&a(&["--set", "main=m1@r1", "--set", "main=m2@r2", "n", "a/b"])).expect("parses");
        assert_eq!(place_body(&p)["sets"], json!({"main": [{"id": "m1", "revision": "r1"}, {"id": "m2", "revision": "r2"}]}));
    }

    #[test]
    fn set_splits_the_slot_at_the_first_equals_and_the_id_at_the_last_at() {
        let s = parse_set("main=org=x@y@rev").expect("parses");
        assert_eq!((s.slot.as_str(), s.id.as_str(), s.revision.as_str()), ("main", "org=x@y", "rev"));
    }

    #[test]
    fn a_malformed_set_is_refused_before_any_request() {
        for bad in ["main", "main=id", "main=@rev", "main=id@", "=id@rev", "", "main=id@rev@"] {
            assert!(parse_set(bad).is_err(), "{bad:?} must be refused");
            assert!(parse_place(&a(&["--set", bad, "n", "a/b"])).is_err(), "{bad:?} must fail the whole parse");
        }
        assert!(parse_place(&a(&["--set"])).is_err(), "a flag with no value");
    }

    #[test]
    fn env_duplicate_and_empty_keys_are_refused() {
        assert!(parse_place(&a(&["--env", "K=1", "--env", "K=2", "n", "a/b"])).is_err());
        assert!(parse_place(&a(&["--env", "=1", "n", "a/b"])).is_err());
        assert!(parse_place(&a(&["--env", "NOEQUALS", "n", "a/b"])).is_err());
        let ok = parse_place(&a(&["--env", "K=a=b", "--env", "E=", "n", "a/b"])).expect("parses");
        assert_eq!(ok.env, vec![("K".to_string(), "a=b".to_string()), ("E".to_string(), String::new())]);
    }

    #[test]
    fn the_workload_ref_needs_exactly_one_slash_and_two_names() {
        assert_eq!(parse_workload_ref("pai-voice/native-voice"), Ok(("pai-voice".to_string(), "native-voice".to_string())));
        for bad in ["voice", "a/b/c", "/b", "a/", "/", "", "../b", "a/.."] {
            assert!(parse_workload_ref(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(parse_place(&a(&["n", "voice"])).is_err());
        assert!(parse_place(&a(&["n"])).is_err());
        assert!(parse_place(&a(&["n", "a/b", "extra"])).is_err());
        assert!(parse_unplace(&a(&["n", "a/b/c"])).is_err());
        assert!(parse_show(&a(&["n", "a"])).is_err());
        assert!(parse_show(&a(&[])).is_err());
    }

    #[test]
    fn the_path_percent_encodes_every_segment() {
        assert_eq!(
            placement_path("awolf", "pai-voice", "native-voice"),
            "/api/cluster/nodes/awolf/node-workloads/pai-voice/native-voice"
        );
        let p = placement_path("a/b", "x?y", "w z");
        assert_eq!(p, "/api/cluster/nodes/a%2Fb/node-workloads/x%3Fy/w%20z");
        assert_eq!(p.matches('/').count(), 7,"no segment can add a slash");
        assert_eq!(list_path("a/../b"), "/api/cluster/nodes/a%2F..%2Fb/node-workloads");
        // Dot segments survive encoding, so they are refused at parse time instead.
        assert!(parse_place(&a(&["..", "a/b"])).is_err());
        assert!(parse_show(&a(&["."])).is_err());
    }

    #[test]
    fn a_409_refusal_shows_the_code_and_the_detail() {
        let text = json!({"error": "gpu_too_small", "detail": "awolf has no GPU with 24 GB free"}).to_string();
        let (code, detail) = parse_refusal(409, &text);
        assert_eq!(format_refusal(&code, &detail), "refused (gpu_too_small): awolf has no GPU with 24 GB free");
        let (code, detail) = parse_refusal(502, "bad gateway");
        assert_eq!(format_refusal(&code, &detail), "refused (http_502): bad gateway");
        assert_eq!(format_refusal("not_found", ""), "refused (not_found)");
    }

    #[test]
    fn the_approve_hint_appears_for_consent_codes_only() {
        let detail = "pai-voice at sha256:0123abcdef9876 is not approved on the node";
        let hint = approve_hint("consent_unapproved", "awolf", "pai-voice", detail).expect("hint");
        assert_eq!(hint, "on awolf, run: noo node workloads approve pai-voice sha256:0123abcdef9876");
        assert!(!hint.starts_with("noo ") && !hint.contains('`'), "plain prose, outside the hint lint");
        let none = approve_hint("consent_none", "awolf", "pai-voice", "no approval recorded").expect("hint");
        assert!(none.ends_with("approve pai-voice <digest>"), "{none}");
        for other in ["gpu_too_small", "not_found", "bad_sets", "image_missing", ""] {
            assert_eq!(approve_hint(other, "awolf", "pai-voice", detail), None, "{other:?}");
        }
    }

    #[test]
    fn a_placed_summary_names_state_image_and_a_short_digest() {
        let resp = json!({
            "node_id": "awolf", "addon": "pai-voice", "workload": "native-voice", "state": "provisioned",
            "image": {"name": "ghcr.io/x/voice:1", "digest": "sha256:0123456789abcdef0123456789abcdef", "id": "i", "artifact": "a"},
        });
        assert_eq!(
            format_placed(&resp),
            "pai-voice/native-voice: placed on awolf — provisioned, image ghcr.io/x/voice:1 sha256:0123456789ab"
        );
        assert_eq!(
            format_unplaced(&json!({"node_id": "awolf", "addon": "pai-voice", "workload": "native-voice", "removed": true})),
            "pai-voice/native-voice: unplaced from awolf"
        );
    }

    fn listing() -> Value {
        json!({
            "node_id": "awolf",
            "node_workloads": [
                {"addon": "pai-voice", "workload": "native-voice", "profile": "int8",
                 "sets": {"main": [{"id": "m", "revision": "r"}]}, "env": {}, "on_controller": false,
                 "state": "provisioned", "reservation": null},
                {"addon": "pai-image", "workload": "sdxl", "profile": null,
                 "sets": {}, "env": {}, "on_controller": true, "state": "provisioned", "reservation": null},
            ],
        })
    }

    #[test]
    fn show_filters_the_list_to_the_named_workload_or_lists_all() {
        let all = select_workloads(&listing(), None);
        assert_eq!(all.len(), 2);
        let one = select_workloads(&listing(), Some(("pai-voice", "native-voice")));
        assert_eq!(one.len(), 1);
        assert_eq!(one[0]["workload"], json!("native-voice"));
        assert!(select_workloads(&listing(), Some(("pai-voice", "sdxl"))).is_empty());
        assert!(select_workloads(&json!({}), None).is_empty());
        assert_eq!(
            workload_row(&one[0]),
            vec!["pai-voice/native-voice", "provisioned", "int8", "main=m@r", "no"]
        );
        assert_eq!(workload_row(&all[1])[2], "-");
        assert_eq!(workload_row(&all[1])[3], "-");
        assert_eq!(parse_show(&a(&["awolf", "pai-voice/native-voice"])), Ok(("awolf".to_string(), Some(("pai-voice".to_string(), "native-voice".to_string())))));
        assert_eq!(parse_show(&a(&["awolf"])), Ok(("awolf".to_string(), None)));
    }
}
