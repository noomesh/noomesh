// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The tailnet policy this project DECLARES, and the verbs that compare the
//! live tailnet to it.
//!
//! `config/tailscale-acl.hujson` has always been the declaration — a
//! deny-by-default policy where tagged workers reach the controller on
//! :8080/:4222/:8443 (the plaintext :8083 grant is gone), members get :443,
//! and kiosk displays get :443 and
//! nothing else. What has never existed is a way to APPLY or CHECK it from
//! the CLI. Only `scripts/bootstrap-controller.sh` pushed it (since retired), and that script was not in the
//! standalone deploy slice: `build.rs` ships the policy file to
//! a dist install and not the script that applies it, so a standalone
//! operator received a declaration with no way to act on it.
//!
//! The gap had a second half. `onboard` hand-printed a `tagOwners` fragment
//! for the operator to paste, and that fragment listed `tag:controller` and
//! `tag:worker` while the declared file had carried `tag:kiosk` since #172.
//! A hand-maintained copy of a declared file is a copy that drifts — the
//! same defect as a compatibility bridge nobody closes and a
//! container compose no longer defines (186b). Both are fixed by reading the
//! declaration instead of restating it: [`declared_tag_owners`] parses the
//! embedded file, and the wizard renders whatever it finds there.

use crate::commands::cluster_provision as tsapi;
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// The declared policy, as embedded by `build.rs`.
///
/// `None` on a crate-only build (`cargo install` outside the repo tree), where
/// `STANDALONE_ASSETS` is deliberately empty. Callers must say so rather than
/// falling back to a hardcoded list — a stale literal that looks authoritative
/// is worse than an honest absence, and is precisely what this module exists
/// to delete.
pub(crate) fn declared_policy() -> Option<&'static str> {
    crate::onboard::standalone::STANDALONE_ASSETS
        .iter()
        .find(|(rel, _, _)| *rel == "config/tailscale-acl.hujson")
        .and_then(|(_, bytes, _)| std::str::from_utf8(bytes).ok())
}

/// Every `"tag:x": [owners]` pair in the declared `tagOwners` block, in file
/// order.
///
/// A deliberately small textual parse, not a HuJSON deserializer: the file
/// carries comments and trailing commas by design (they are load-bearing
/// documentation — the `tag:worker` co-owner note is why client-side minting
/// works at all), and a strict JSON reader would reject it. We only need the
/// pairs, and the shape is ours.
pub(crate) fn declared_tag_owners(policy: &str) -> Vec<(String, String)> {
    let Some(start) = policy.find("\"tagOwners\"") else {
        return Vec::new();
    };
    let Some(open) = policy[start..].find('{').map(|i| start + i + 1) else {
        return Vec::new();
    };
    let Some(close) = policy[open..].find('}').map(|i| open + i) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in policy[open..close].lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let Some(rest) = line.strip_prefix('"') else { continue };
        let Some(end) = rest.find('"') else { continue };
        let tag = &rest[..end];
        if !tag.starts_with("tag:") {
            continue;
        }
        let Some(colon) = rest[end..].find(':').map(|i| end + i + 1) else { continue };
        let owners = rest[colon..].trim().trim_end_matches(',').trim();
        out.push((tag.to_string(), owners.to_string()));
    }
    out
}


/// Every grant in a policy as a normalised `(src, dst)` pair, in order.
///
/// A grant is what the policy IS: "these sources may reach these
/// destinations". Two policies that carry the same grants and the same tag
/// owners permit exactly the same traffic, whatever else differs between
/// their bytes. This is the comparison that answers the operator's real
/// question — "would pushing change who can reach what?" — and it is textual
/// for the same reason `declared_tag_owners` is: HuJSON, and the shape is ours.
pub(crate) fn grants(policy: &str) -> Vec<(String, String)> {
    fn bracket_after(s: &str, key: &str) -> Vec<(usize, String)> {
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(i) = s[from..].find(key) {
            let at = from + i;
            let Some(open) = s[at..].find('[').map(|x| at + x) else { break };
            let Some(close) = s[open..].find(']').map(|x| open + x) else { break };
            let inner: String = s[open + 1..close]
                .split(',')
                .map(|x| x.trim().trim_matches('"'))
                .filter(|x| !x.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            out.push((at, inner));
            from = close;
        }
        out
    }
    // Parsed first: the shape of the object decides which dst belongs to which
    // src, not the order the keys happen to be written in.
    if let Some(v) = parse_hujson(policy) {
        let join = |a: &serde_json::Value| {
            a.as_array()
                .map(|xs| xs.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","))
                .unwrap_or_default()
        };
        let mut out = Vec::new();
        for key in ["grants", "acls"] {
            for rule in v[key].as_array().into_iter().flatten() {
                if rule.get("src").is_some() && rule.get("dst").is_some() {
                    out.push((join(&rule["src"]), join(&rule["dst"])));
                }
            }
        }
        return out;
    }
    let stripped = strip_comments(policy);
    let srcs = bracket_after(&stripped, "\"src\"");
    let dsts = bracket_after(&stripped, "\"dst\"");
    // Unparseable: pair each src with the dst inside the SAME rule object —
    // the `{ … }` around it. Pairing with "the next dst" was wrong whenever a
    // rule writes dst before src, which is exactly how Tailscale's API returns
    // a policy (keys sorted): every src took the following rule's dst, and the
    // check reported six grants changing on a policy that matched
    // (2026-10-01). A src with no dst in its object is dropped, not guessed.
    let mut out = Vec::new();
    for (spos, src) in &srcs {
        let start = stripped[..*spos].rfind('{').unwrap_or(0);
        let end = stripped[*spos..].find('}').map(|x| spos + x).unwrap_or(stripped.len());
        if let Some((_, dst)) = dsts.iter().find(|(dpos, _)| *dpos > start && *dpos < end) {
            out.push((src.clone(), dst.clone()));
        }
    }
    out
}

/// The policy as JSON: HuJSON is JSON plus `//` comments and trailing commas.
/// `None` when that does not parse, and callers fall back to reading text.
fn parse_hujson(policy: &str) -> Option<serde_json::Value> {
    serde_json::from_str(&drop_trailing_commas(&strip_comments(policy))).ok()
}

/// Remove a comma that is followed (after whitespace) by `}` or `]`, outside
/// strings — the one place HuJSON's grammar is looser than JSON's.
fn drop_trailing_commas(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let (mut in_str, mut escaped) = (false, false);
    for (i, &c) in chars.iter().enumerate() {
        if in_str {
            out.push(c);
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_str = false,
                _ => {}
            }
            continue;
        }
        if c == '"' {
            in_str = true;
        } else if c == ',' {
            let next = chars[i + 1..].iter().find(|n| !n.is_whitespace());
            if matches!(next, Some('}') | Some(']')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// Every leaf of a parsed policy as `path = value`. Object keys are paths, so
/// key order and line breaks cannot make two equal policies differ; array
/// positions stay, because the order of rules is the author's.
fn canonical_lines(v: &serde_json::Value, path: &str, out: &mut std::collections::BTreeSet<String>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, child) in m {
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                canonical_lines(child, &p, out);
            }
        }
        serde_json::Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                canonical_lines(child, &format!("{path}[{i}]"), out);
            }
        }
        leaf => {
            out.insert(format!("{path} = {leaf}"));
        }
    }
}

/// The policy with `//` comments removed, line by line. Comments are where the
/// declared file keeps its reasons, and the console strips them on every
/// save — so they are the first thing to differ and the last thing that
/// matters to the tailnet.
fn strip_comments(policy: &str) -> String {
    policy
        .lines()
        .map(|l| match l.find("//") {
            // A `//` inside a quoted string (a URL) is not a comment. The only
            // strings in this file are tags, groups and ports, none of which
            // carry one, so the simple rule holds for our shape.
            Some(i) if !l[..i].contains('"') || l[..i].matches('"').count() % 2 == 0 => &l[..i],
            _ => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Lines that carry meaning, normalised so formatting cannot make two equal
/// policies look different: comments gone, whitespace collapsed, trailing
/// commas dropped, empties removed.
pub(crate) fn meaningful_lines(policy: &str) -> std::collections::BTreeSet<String> {
    if let Some(v) = parse_hujson(policy) {
        let mut out = std::collections::BTreeSet::new();
        canonical_lines(&v, "", &mut out);
        return out;
    }
    strip_comments(policy)
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .map(|l| l.trim_end_matches(',').trim().to_string())
        .filter(|l| !l.is_empty() && l != "{" && l != "}" && l != "[" && l != "]")
        .collect()
}

/// How a live policy stands against the declaration, from most to least
/// consequential. A caller prints ALL of it; the point is that "differs" on
/// its own tells an operator nothing they can act on, and a wholesale push
/// on an unexplained difference is how a working grant disappears.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PolicyDrift {
    pub grants_only_declared: Vec<(String, String)>,
    pub grants_only_live: Vec<(String, String)>,
    pub lines_only_declared: Vec<String>,
    pub lines_only_live: Vec<String>,
    pub bytes_differ: bool,
}

impl PolicyDrift {
    /// Traffic would change on push.
    pub fn changes_reachability(&self) -> bool {
        !self.grants_only_declared.is_empty() || !self.grants_only_live.is_empty()
    }
    /// Something other than comments and whitespace differs.
    pub fn changes_content(&self) -> bool {
        self.changes_reachability()
            || !self.lines_only_declared.is_empty()
            || !self.lines_only_live.is_empty()
    }
}

pub(crate) fn drift(declared: &str, live: &str) -> PolicyDrift {
    let dg = grants(declared);
    let lg = grants(live);
    let dl = meaningful_lines(declared);
    let ll = meaningful_lines(live);
    PolicyDrift {
        grants_only_declared: dg.iter().filter(|g| !lg.contains(g)).cloned().collect(),
        grants_only_live: lg.iter().filter(|g| !dg.contains(g)).cloned().collect(),
        lines_only_declared: dl.difference(&ll).cloned().collect(),
        lines_only_live: ll.difference(&dl).cloned().collect(),
        bytes_differ: declared.trim() != live.trim(),
    }
}

/// `noo security tailnet policy [--push] [--yes]`
///
/// Default is a READ: fetch the live policy and say how it differs from the
/// declaration. `--push` replaces the live policy with the declared one, after
/// validating it through Tailscale's own endpoint and writing the current
/// policy to a backup file first.
///
/// The push is wholesale and that is the point — the declaration is the
/// authority, and a console-only edit is meant to be reverted. It is also why
/// the read is the default: "wholesale" and "unattended" should never be the
/// same command.
pub fn tailnet_policy(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (mut push, mut merge, mut yes) = (false, false, false);
    for a in args {
        match a.as_str() {
            "--push" => push = true,
            "--merge" => merge = true,
            "--yes" | "-y" => yes = true,
            _ => return Err(Unhandled),
        }
    }
    if push && merge {
        fail(g.json, ExitCode::Generic, "push_and_merge",
            "--push replaces the whole policy and --merge only adds to it; pick one",
            Some("noo security tailnet policy --merge   # safe on a tailnet you already use"));
    }
    if merge {
        return run_merge(g, yes);
    }

    let Some(declared) = declared_policy() else {
        fail(g.json, ExitCode::Generic, "no_declared_policy",
            "this noo binary carries no embedded tailnet policy (built outside the repo tree)",
            Some("use a released noo-cli, or run from a repo checkout"));
    };

    let live = match tsapi::fetch_live_acl() {
        Ok((body, _etag)) => body,
        Err(e) => {
            fail(g.json, ExitCode::Generic, "acl_read_failed", &e, None);
        }
    };

    let declared_tags = declared_tag_owners(declared);
    let live_tags = declared_tag_owners(&live);
    let missing: Vec<&(String, String)> = declared_tags
        .iter()
        .filter(|(t, _)| !live_tags.iter().any(|(lt, _)| lt == t))
        .collect();
    let extra: Vec<&(String, String)> = live_tags
        .iter()
        .filter(|(t, _)| !declared_tags.iter().any(|(dt, _)| dt == t))
        .collect();
    // Byte equality is still the only complete "in sync" — the push is
    // wholesale — but it is not the only thing worth saying. The console
    // strips comments on every save, so a policy pushed from this exact file
    // reads back "different" forever. What the operator needs is WHICH kind
    // of different: would reachability change, would content change, or
    // only bytes.
    let d = drift(declared, &live);
    let in_sync = !d.bytes_differ;

    if g.json {
        println!("{}", serde_json::json!({
            "in_sync": in_sync,
            "declared_tags": declared_tags.iter().map(|(t, _)| t).collect::<Vec<_>>(),
            "live_tags": live_tags.iter().map(|(t, _)| t).collect::<Vec<_>>(),
            "missing_from_live": missing.iter().map(|(t, _)| t).collect::<Vec<_>>(),
            "only_in_live": extra.iter().map(|(t, _)| t).collect::<Vec<_>>(),
            "changes_reachability": d.changes_reachability(),
            "changes_content": d.changes_content(),
            "grants_only_declared": d.grants_only_declared,
            "grants_only_live": d.grants_only_live,
            "lines_only_declared": d.lines_only_declared,
            "lines_only_live": d.lines_only_live,
            "pushed": false,
        }));
        return Ok(if in_sync { 0 } else { 1 });
    }

    println!("{}", ui::header("tailnet policy", Some("declared vs live")));
    let rows: Vec<Vec<String>> = declared_tags
        .iter()
        .map(|(t, o)| {
            let present = live_tags.iter().any(|(lt, _)| lt == t);
            vec![
                ui::glyph_cell(if present { Glyph::Ok } else { Glyph::Err }),
                t.clone(),
                o.clone(),
                if present { ui::muted("live") } else { ui::warn("NOT on the tailnet") }.to_string(),
            ]
        })
        .collect();
    print!("{}", ui::table(
        &[Col::left(""), Col::left("declared tag"), Col::left("owners"), Col::left("state")],
        &rows,
    ));
    println!();
    for (t, _) in &extra {
        println!("{}", ui::status_line(Glyph::Warn, &format!(
            "{t} exists on the tailnet but is NOT declared — the next push deletes it")));
    }
    if in_sync {
        println!("{}", ui::status_line(Glyph::Ok, "the live policy matches the declaration exactly"));
        return Ok(0);
    }
    // Most consequential first. An operator reading top-down should meet the
    // thing that changes who-can-reach-what before the thing that changes a
    // comma.
    if d.changes_reachability() {
        println!("{}", ui::status_line(Glyph::Err, "pushing would CHANGE REACHABILITY"));
        for (src, dst) in &d.grants_only_declared {
            println!("    {}  {}", ui::warn("+ grant"), ui::muted(&format!("{src} → {dst}   (declared, not live: push ADDS it)")));
        }
        for (src, dst) in &d.grants_only_live {
            println!("    {}  {}", ui::warn("- grant"), ui::muted(&format!("{src} → {dst}   (live, not declared: push REMOVES it)")));
        }
        println!();
    }
    if !d.lines_only_declared.is_empty() || !d.lines_only_live.is_empty() {
        println!("{}", ui::status_line(Glyph::Warn, "content differs (comments and whitespace ignored)"));
        for l in &d.lines_only_declared {
            println!("    {}  {l}", ui::muted("declared only:"));
        }
        for l in &d.lines_only_live {
            println!("    {}  {l}", ui::muted("live only:    "));
        }
        println!();
    }
    if !d.changes_content() {
        println!("{}", ui::status_line(Glyph::Ok,
            "same grants, same owners, same content — only comments or formatting differ"));
        println!("{}", ui::muted("the console strips comments on save; a push restores them and changes nothing the tailnet enforces"));
    } else {
        println!("{}", ui::status_line(Glyph::Warn, "the live policy differs from the declaration"));
    }

    if !push {
        ui::guide(&[
            ("noo security tailnet policy --merge", "ADD what noomesh declares; keeps everything already there"),
        ]);
        return Ok(1);
    }

    crate::commands::confirm_destructive(
        g,
        yes,
        "REPLACE the tailnet's ENTIRE policy with the declared one —",
        "every console-only edit is erased",
    );

    match tsapi::push_acl(declared) {
        Ok(backup) => {
            println!("{}", ui::status_line(Glyph::Ok, &format!(
                "policy pushed — previous policy saved to {}", backup.display())));
            Ok(0)
        }
        Err(e) => {
            fail(g.json, ExitCode::Generic, "acl_push_failed", &e, None);
        }
    }
}

/// Fetch the live policy and work out what an additive merge would add.
/// Returns the merged policy (as JSON text, ready to post) and the plan.
/// Shared by `--merge` and onboarding so there is one merge, not two.
pub(crate) fn plan_merge() -> Result<(String, crate::commands::tailnet_merge::MergePlan), String> {
    use crate::commands::tailnet_merge::{merge_additive, parse_policy};
    let declared = declared_policy()
        .ok_or("this noo binary carries no embedded tailnet policy (built outside the repo tree)")?;
    let (live, _etag) = tsapi::fetch_live_acl()?;
    let (merged, plan) = merge_additive(&parse_policy(&live)?, &parse_policy(declared)?)?;
    let text = serde_json::to_string_pretty(&merged).map_err(|e| e.to_string())?;
    Ok((text, plan))
}

/// The plan, one line per addition. Every line is a `+`: there is no `-`.
pub(crate) fn plan_lines(plan: &crate::commands::tailnet_merge::MergePlan) -> Vec<String> {
    let mut out = Vec::new();
    for t in &plan.tags_added {
        out.push(format!("+ tag    {t}"));
    }
    for (t, o) in &plan.owners_added {
        out.push(format!("+ owner  {o} of {t}"));
    }
    for a in &plan.acls_added {
        out.push(format!("+ grant  {a}"));
    }
    out
}

/// `noo security tailnet policy --merge [--yes]`
fn run_merge(g: &Globals, yes: bool) -> Result<i32, Unhandled> {
    let (merged, plan) = match plan_merge() {
        Ok(x) => x,
        Err(e) => fail(g.json, ExitCode::Generic, "merge_plan_failed", &e, None),
    };
    if g.json && (plan.is_empty() || !yes) {
        println!("{}", serde_json::json!({
            "tags_added": plan.tags_added,
            "owners_added": plan.owners_added,
            "acls_added": plan.acls_added,
            "applied": false,
        }));
        return Ok(if plan.is_empty() { 0 } else { 1 });
    }
    if !g.json {
        println!("{}", ui::header("tailnet policy", Some("additive merge")));
    }
    if plan.is_empty() {
        println!("{}", ui::status_line(Glyph::Ok,
            "the live policy already contains everything noomesh declares — nothing to add"));
        return Ok(0);
    }
    for l in plan_lines(&plan) {
        println!("    {}", ui::warn(&l));
    }
    println!();
    println!("{}", ui::muted(
        "nothing is removed — your own groups, tags, grants and ssh rules stay exactly as they are. \
         The live policy's comments are not carried over; the current policy is backed up first."));
    // Reused for its handling of --yes, --json and a non-TTY stdin; the
    // change it guards only adds.
    crate::commands::confirm_destructive(g, yes, "ADD the lines above to the live tailnet policy", "(nothing is removed)");
    match tsapi::push_acl(&merged) {
        Ok(backup) => {
            println!("{}", ui::status_line(Glyph::Ok, &format!(
                "added — previous policy saved to {}", backup.display())));
            Ok(0)
        }
        Err(e) => fail(g.json, ExitCode::Generic, "acl_merge_failed", &e, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The declared file is the authority and it must parse. If this goes
    /// quiet the wizard silently stops offering tags, which is the failure
    /// this module was written to remove.
    #[test]
    fn the_embedded_policy_parses_into_tags() {
        let Some(p) = declared_policy() else {
            return; // crate-only build: nothing embedded, nothing to assert
        };
        let tags = declared_tag_owners(p);
        assert!(!tags.is_empty(), "declared policy parsed to ZERO tagOwners");
        for want in crate::commands::cluster_provision::API_DECLARED_TAGS {
            assert!(
                tags.iter().any(|(t, _)| t == want),
                "{want} is writable over the API but did not parse out of the declared policy: {tags:?}"
            );
        }
    }

    /// Comments and trailing commas are load-bearing in this file — they carry
    /// the reasons — so the parser must step over them rather than the file
    /// having to become strict JSON.
    #[test]
    fn comments_and_trailing_commas_are_skipped() {
        let p = "{\n\t\"tagOwners\": {\n\t\t// why this one is co-owned\n\t\t\"tag:controller\": [\"autogroup:admin\"],\n\t\t\"tag:worker\": [\"autogroup:admin\", \"tag:controller\"],\n\t},\n}";
        let tags = declared_tag_owners(p);
        assert_eq!(tags.len(), 2, "{tags:?}");
        assert_eq!(tags[0].0, "tag:controller");
        assert_eq!(tags[1].1, "[\"autogroup:admin\", \"tag:controller\"]");
    }

    /// PINNED AS SOURCE, not behaviour. The onboarding wizard used to print a
    /// hardcoded `tagOwners` fragment, and it drifted silently: `tag:kiosk`
    /// entered the declared file in #172 and never entered those lines, so a
    /// fresh install pasted a policy missing a tag this CLI can write.
    ///
    /// A behavioural test cannot catch the regression, because re-adding the
    /// drift means writing a NEW literal that no assertion knows to look for.
    /// The needles are assembled at runtime so this test's own source does not
    /// match itself.
    #[test]
    fn the_wizard_never_spells_a_tag_out() {
        let src = include_str!("../onboard/steps.rs");
        for needle in ["tag:controller", "tag:worker", "tag:kiosk"] {
            let literal = format!("{}{}{}", '\\', '"', needle);
            assert!(
                !src.contains(&literal),
                "onboard/steps.rs spells out {needle} — render it from \
                 config/tailscale-acl.hujson via declared_tag_owners() instead, \
                 or it will drift the way the last one did"
            );
        }
    }

    #[test]
    fn api_shaped_policy_with_dst_before_src_matches_the_declaration() {
        // Tailscale's API returns keys sorted (dst before src) and arrays one
        // item per line. The textual pairing read that as six grants moving.
        let declared = "{\n  // why\n  \"tagOwners\": {\"tag:worker\": [\"autogroup:admin\"],},\n  \"grants\": [\n    {\"src\": [\"tag:worker\"], \"dst\": [\"tag:controller:8080\", \"tag:controller:4222\"], \"ip\": [\"*\"]},\n    {\"src\": [\"autogroup:admin\"], \"dst\": [\"*:*\"], \"ip\": [\"*\"]},\n  ],\n}";
        let live = r#"{
  "grants": [
    {
      "dst": [
        "tag:controller:8080",
        "tag:controller:4222"
      ],
      "ip": ["*"],
      "src": ["tag:worker"]
    },
    {
      "dst": ["*:*"],
      "ip": ["*"],
      "src": ["autogroup:admin"]
    }
  ],
  "tagOwners": {"tag:worker": ["autogroup:admin"]}
}"#;
        let d = drift(declared, live);
        assert!(!d.changes_reachability(), "{d:?}");
        assert!(!d.changes_content(), "{d:?}");

        // A real difference still shows, and only that difference.
        let live_extra = live.replace("\"tag:controller:4222\"", "\"tag:controller:4222\",\n        \"tag:controller:8083\"");
        let d = drift(declared, &live_extra);
        assert!(d.changes_reachability(), "{d:?}");
        assert_eq!(d.lines_only_live, vec!["grants[0].dst[2] = \"tag:controller:8083\"".to_string()], "{d:?}");
        assert!(d.lines_only_declared.is_empty(), "{d:?}");
    }

    #[test]
    fn trailing_commas_go_but_commas_in_strings_stay() {
        assert_eq!(drop_trailing_commas("{\"a\": [1, 2,], \"b\": \"x,]\",}"), "{\"a\": [1, 2], \"b\": \"x,]\"}");
    }

    #[test]
    fn unparseable_policy_still_pairs_within_each_rule() {
        // Not JSON (an unquoted key), so the textual reader runs.
        let p = "{ acls: [ { \"dst\": [\"tag:a:1\"], \"src\": [\"tag:x\"] }, { \"dst\": [\"tag:b:2\"], \"src\": [\"tag:y\"] } ] }";
        assert!(parse_hujson(p).is_none());
        assert_eq!(grants(p), vec![("tag:x".into(), "tag:a:1".into()), ("tag:y".into(), "tag:b:2".into())]);
    }

    #[test]
    fn grants_pair_each_src_with_its_dst() {
        let p = r#"{
          "acls": [
            { "action": "accept", "src": ["tag:worker"], "dst": ["tag:controller:8080", "tag:controller:4222"] },
            // a comment between rules
            { "action": "accept", "src": ["tag:kiosk"],  "dst": ["tag:controller:443"] },
          ],
        }"#;
        let g = grants(p);
        assert_eq!(g.len(), 2, "{g:?}");
        assert_eq!(g[0], ("tag:worker".into(), "tag:controller:8080,tag:controller:4222".into()));
        assert_eq!(g[1], ("tag:kiosk".into(), "tag:controller:443".into()));
    }

    /// The case the operator actually hit: a policy pushed from this file and
    /// read back from the console with its comments stripped. It must read as
    /// formatting-only, or every check after every push says "differs" and
    /// the verb teaches people to ignore it.
    #[test]
    fn comments_and_formatting_alone_do_not_change_content() {
        let declared = "{\n\t// why\n\t\"tagOwners\": {\n\t\t\"tag:worker\": [\"autogroup:admin\"],\n\t},\n\t\"acls\": [\n\t\t// reason\n\t\t{\"action\": \"accept\", \"src\": [\"tag:worker\"], \"dst\": [\"tag:controller:8080\"]},\n\t],\n}";
        let live = "{\n  \"tagOwners\": {\n    \"tag:worker\": [\"autogroup:admin\"]\n  },\n  \"acls\": [\n    {\"action\": \"accept\", \"src\": [\"tag:worker\"], \"dst\": [\"tag:controller:8080\"]}\n  ]\n}";
        let d = drift(declared, live);
        assert!(d.bytes_differ);
        assert!(!d.changes_reachability(), "{d:?}");
        assert!(!d.changes_content(), "{d:?}");
    }

    /// A grant present live and absent from the declaration is the dangerous
    /// direction: a push REMOVES it, and the host stays reachable while the
    /// port stops answering. It must be named, as a removal.
    #[test]
    fn a_live_only_grant_is_reported_as_a_removal() {
        let declared = "{\"acls\": [{\"src\": [\"tag:worker\"], \"dst\": [\"tag:controller:8080\"]}]}";
        let live = "{\"acls\": [{\"src\": [\"tag:worker\"], \"dst\": [\"tag:controller:8080\"]}, {\"src\": [\"tag:worker\"], \"dst\": [\"tag:controller:3100\"]}]}";
        let d = drift(declared, live);
        assert!(d.changes_reachability());
        assert_eq!(d.grants_only_live, vec![("tag:worker".to_string(), "tag:controller:3100".to_string())]);
        assert!(d.grants_only_declared.is_empty());
    }

    #[test]
    fn identical_policies_have_no_drift() {
        let p = "{\"acls\": [{\"src\": [\"a\"], \"dst\": [\"b:1\"]}]}";
        assert_eq!(drift(p, p), PolicyDrift::default());
    }

    #[test]
    fn a_policy_with_no_tag_owners_yields_nothing() {
        assert!(declared_tag_owners("{\n\t\"acls\": [],\n}").is_empty());
    }
}
