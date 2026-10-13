// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Bash tab completion for `noo` (and the `pai` alias) — ONE installer,
//! called from every path that puts a binary on a box: onboard (controller),
//! enroll (worker/companion, both lanes), and upgrade (refresh from the new
//! binary; install when missing).
//!
//! Why one place: completions used to be installed only by onboard. A worker
//! enrolled with `noo enroll` never ran onboard, and `noo upgrade` only
//! refreshed a file that already existed — so a worker box never had tab
//! completion at all (HOST3, 2026-09-01). Any install path that forgets to
//! call this is the same bug again.

use std::path::PathBuf;
use std::process::Command;

/// Where the per-user completion lives. bash-completion (Linux and brew's
/// bash-completion@2) both load this XDG dir lazily, so no rc edit is needed.
fn user_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok().filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(".local/share/bash-completion/completions"))
}

/// Install (or, with `refresh`, rewrite) the completion from the running
/// binary. Returns the written path, `None` when nothing was written —
/// either already present without `refresh`, or a failure (best-effort,
/// never fatal: a missing completion is an inconvenience, not an outage).
pub fn ensure_installed(refresh: bool) -> Option<PathBuf> {
    // After an in-place upgrade the running process's own path reads
    // "…/noo (deleted)" on Linux (the old inode was unlinked), so spawning
    // current_exe() fails silently — which is why `noo upgrade` never
    // installed a completion on a box that had none (HOST3, 2026-09-02).
    // Strip the marker: the path itself now holds the NEW binary.
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().trim_end_matches(" (deleted)").to_string())
        .unwrap_or_else(|_| "noo".into());
    ensure_installed_with(std::path::Path::new(&exe), refresh)
}

/// Same, with the binary named explicitly (the upgrade passes the path it
/// just wrote).
pub fn ensure_installed_with(exe: &std::path::Path, refresh: bool) -> Option<PathBuf> {
    let dir = user_dir()?;
    let target = dir.join("noo");
    if target.exists() && !refresh {
        return None;
    }
    let out = Command::new(exe).args(["completions", "bash"]).output().ok()?;
    if !out.status.success() || out.stdout.is_empty() {
        return None;
    }
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::write(&target, &out.stdout).ok()?;
    // The alias era: `pai` still resolves, so it completes too.
    let _ = std::fs::write(dir.join("pai"), &out.stdout);
    Some(target)
}

/// Dynamic completion candidates for an argument position — task ids,
/// node names, service names, channel names, usernames — fetched at
/// <Tab> time (`noo completions candidates <group> <verb>`; the shell
/// function wraps the call in `timeout 3`, so an unreachable gateway
/// costs a moment, never a hang).
///
/// Empty output means NO completions — the shim offers nothing. It used to
/// mean "fall back to filenames", which turned every leaf command into a
/// directory listing: `noo doctor node <Tab>` printed the operator's whole
/// home directory (host8, 2026-09-05). Filenames are now opt-in, requested
/// with the [`FILES`] sentinel and decided by [`wants_path`] from the usage
/// table, so a command that takes a path keeps file completion and a command
/// that does not stays quiet.
pub const FILES: &str = "__files__";

/// Does the next word at this position name a filesystem path?
///
/// Derived from `usage::USAGE` rather than a hand-kept list, so a new
/// command declaring `<file>` gets file completion for free and one that
/// stops taking a path loses it. Two shapes count:
///
///   * the previous typed word is a flag the usage line pairs with a path
///     placeholder — `noo migrate export -o <Tab>`;
///   * nothing is pending and the command's FIRST positional is a path —
///     `noo heartbeat import <Tab>`.
///
/// `typed` is everything after the command words, as the shell has it.
pub fn wants_path(words: &[String], typed: &[String]) -> bool {
    let refs: Vec<&str> = words.iter().map(String::as_str).collect();
    let Some((syntax, _)) = crate::usage::lookup(&refs) else {
        return false;
    };
    if let Some(prev) = typed.last() {
        if prev.starts_with('-') {
            return flag_takes_path(syntax, prev);
        }
    }
    // No flag pending: only the FIRST positional is offered as a path.
    // `noo rag ingest a.txt <Tab>` is repeatable (`<file>...`) and keeps it.
    if !typed.is_empty() && !syntax.contains("...") {
        return false;
    }
    first_positional_is_path(syntax)
}

/// True when `syntax` pairs `flag` with a path-shaped placeholder, e.g.
/// `[-o <file>]`, `[--sops-file <path>]`, `[--data-root <dir>]`.
fn flag_takes_path(syntax: &str, flag: &str) -> bool {
    let mut toks = syntax.split_whitespace().peekable();
    while let Some(t) = toks.next() {
        // Strip the bracket/pipe furniture the table uses around flags.
        if t.trim_matches(|c| c == '[' || c == ']' || c == '|')
            .split('|')
            .any(|alt| alt == flag)
        {
            if let Some(next) = toks.peek() {
                return placeholder_is_path(next);
            }
        }
    }
    false
}

/// The first positional placeholder, if the syntax opens with one.
fn first_positional_is_path(syntax: &str) -> bool {
    match syntax.split_whitespace().next() {
        Some(t) if t.starts_with('<') || t.starts_with("[<") => placeholder_is_path(t),
        _ => false,
    }
}

/// Is `<…>` a path? Named placeholders (`<file>`, `<path>`, `<dir>`, `<f>`,
/// `<archive>`, `<ca_path>`) plus anything carrying an extension
/// (`<out.tar.gz>`, `<noo1.blob>`, `<file.sig>`).
fn placeholder_is_path(tok: &str) -> bool {
    let name = tok.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '.');
    const NAMED: &[&str] = &["file", "path", "dir", "f", "archive", "ca_path", "out"];
    NAMED.contains(&name)
        || name.ends_with("_path")
        || name.ends_with("_file")
        || name.ends_with("-file")
        || (name.contains('.') && !name.starts_with('.'))
}

pub fn candidates(g: &crate::Globals, group: &str, verb: &str) -> Vec<String> {
    let api = |path: &str, list: &str, field: &str| -> Vec<String> {
        crate::http::get_json_try(g, path, true, 3)
            .ok()
            .and_then(|b| b[list].as_array().cloned())
            .map(|a| a.iter().filter_map(|x| x[field].as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    match (group, verb) {
        ("heartbeat", "run" | "toggle" | "set-schedule" | "remove" | "history") => api("/api/heartbeat/tasks", "tasks", "id"),
        // Every `cluster` verb whose first argument is a node, DERIVED from
        // the usage table rather than listed here. The hand-kept list this
        // replaces named six verbs while seventeen take a node, so `cluster
        // logs`, `desired`, `show`, `clean`, `unplace` and eight more
        // offered nothing — and the operator hitting Tab after `logs`
        // reasonably concluded the CLI did not know its own fleet
        // (2026-09-21). A list maintained beside the thing it describes
        // goes stale; this one cannot.
        ("cluster", v) if verb_takes_a_node(v) => api("/api/cluster/nodes", "nodes", "id"),
        ("security", "user") => api("/api/security/users", "users", "username"),
        // The names `provision` takes are the registry's per-consumer keys,
        // short form (worker, trellion, trellion-intel, evolve) — static, no
        // gateway needed.
        ("security", "service-key provision") => provisionable_consumers(),
        // The other key verbs take a LIVE consumer name as issued
        // (`svc:worker`). Offering them is what stops a bare `worker` being
        // typed and minted as a second consumer beside the real one.
        ("security", "service-key rotate" | "service-key revoke" | "service-key retire" | "service-key set-quota") => {
            let mut v: Vec<String> = crate::http::get_json_try(g, "/api/security/service-keys", true, 3)
                .ok()
                .and_then(|b| b["keys"].as_array().cloned())
                .map(|a| {
                    a.iter()
                        .filter(|k| k["active"].as_bool().unwrap_or(false))
                        .filter_map(|k| k["consumer"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            v.sort_unstable();
            v.dedup();
            v
        }
        ("channels", "test") => crate::http::get_json_try(g, "/api/channels/status", true, 3)
            .ok()
            .and_then(|b| b["channels"].as_object().map(|m| m.keys().cloned().collect()))
            .unwrap_or_default(),
        ("stack", "logs" | "restart") => {
            // Local: the running containers minus the instance prefix.
            let prefix = format!("{}-", crate::envfile::container_prefix());
            std::process::Command::new("docker")
                .args(["ps", "--format", "{{.Names}}"])
                .output()
                .ok()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .filter_map(|l| l.strip_prefix(&prefix).map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

/// Every `NOO_SVC_KEY_*` in the registry, as the short name `provision`
/// takes: `NOO_SVC_KEY_TRELLION_INTEL` → `trellion-intel`.
pub(crate) fn provisionable_consumers() -> Vec<String> {
    let mut v: Vec<String> = crate::commands::secrets::registry()
        .filter_map(|s| s.key.strip_prefix("NOO_SVC_KEY_"))
        .map(|k| k.to_ascii_lowercase().replace('_', "-"))
        .collect();
    v.sort_unstable();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names come from the registry, not a list kept beside it; evolve
    /// arrived there on 2026-09-24 and appears here with no edit.
    #[test]
    fn provision_offers_every_registry_consumer_by_its_short_name() {
        let names = provisionable_consumers();
        for n in ["evolve", "trellion", "trellion-intel", "worker"] {
            assert!(names.iter().any(|x| x == n), "{n} missing from {names:?}");
        }
        assert!(names.iter().all(|n| !n.contains("NOO_SVC_KEY") && !n.contains('_')));
    }

    fn w(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn a_leaf_command_asks_for_nothing() {
        // The bug: these offered no candidates, the shim fell back to
        // filenames, and <Tab> listed the operator's home directory.
        for cmd in ["doctor node", "cluster status", "auth status", "whoami"] {
            assert!(!wants_path(&w(cmd), &[]), "{cmd} must not request files");
        }
    }

    #[test]
    fn a_command_whose_first_positional_is_a_path_asks_for_files() {
        for cmd in ["heartbeat import", "bundle export", "rag ingest", "migrate import"] {
            assert!(wants_path(&w(cmd), &[]), "{cmd} must request files");
        }
    }

    #[test]
    fn a_flag_paired_with_a_path_asks_for_files() {
        assert!(wants_path(&w("migrate export"), &w("-o")));
        assert!(wants_path(&w("config show"), &w("--config")));
        assert!(wants_path(&w("security secrets audit"), &w("--sops-file")));
        // …and a flag that takes something else does not.
        assert!(!wants_path(&w("cluster set-config"), &w("--tier")));
        assert!(!wants_path(&w("inference run"), &w("-m")));
    }

    #[test]
    fn only_the_first_positional_is_a_path_unless_repeatable() {
        // `noo heartbeat import <file>` takes exactly one.
        assert!(!wants_path(&w("heartbeat import"), &w("dump.json")));
        // `noo rag ingest <file>...` takes many.
        assert!(wants_path(&w("rag ingest"), &w("a.txt")));
    }

    #[test]
    fn an_unknown_command_asks_for_nothing() {
        assert!(!wants_path(&w("definitely not a command"), &[]));
    }

    #[test]
    fn placeholders_are_classified_by_name_or_extension() {
        for t in ["<file>", "[<ca_path>]", "<archive>", "<out.tar.gz>", "<noo1.blob>", "<f>"] {
            assert!(placeholder_is_path(t), "{t}");
        }
        for t in ["<node>", "<model>", "<backend>", "<prompt>", "<key>", "<n>"] {
            assert!(!placeholder_is_path(t), "{t}");
        }
    }
}


/// Does `cluster <verb>` take a node as its first argument?
///
/// Read from `usage::USAGE`, which is already the single source of truth
/// for syntax and is pinned by `usage_table_matches_registry_exactly`. A
/// verb is node-first when its syntax begins with `<node>` (required) or
/// `[<node>` (optional, as `cluster logs` and `sync-images` are).
pub(crate) fn verb_takes_a_node(verb: &str) -> bool {
    crate::usage::USAGE.iter().any(|(words, syntax, _)| {
        words.first() == Some(&"cluster")
            && words.get(1) == Some(&verb)
            && (syntax.starts_with("<node>") || syntax.starts_with("[<node>"))
    })
}

#[cfg(test)]
mod node_completion_tests {
    use super::verb_takes_a_node;

    /// The operator hit Tab after `noo cluster logs ` and got nothing, and
    /// reasonably read that as the CLI not knowing its own fleet
    /// (2026-09-21). `logs` takes `[<node>]`, so the optional form must
    /// count as node-first or the most-used verb stays silent.
    #[test]
    fn logs_completes_a_node_even_though_its_node_is_optional() {
        assert!(verb_takes_a_node("logs"), "`cluster logs <Tab>` offers no nodes");
    }

    /// The hand-kept list this replaced named six verbs while seventeen
    /// take a node. These are the ones it silently omitted.
    #[test]
    fn the_verbs_the_old_hand_kept_list_missed_are_all_covered() {
        for v in [
            "desired", "show", "forget", "unplace", "set-config",
            "add-companion", "add-monitor", "upgrade-hostd", "upgrade-applier",
            "restart-backends", "import-model", "clean", "logs",
        ] {
            assert!(verb_takes_a_node(v), "`cluster {v} <Tab>` offers no nodes");
        }
    }

    /// Still derived, not blanket: a verb that takes no node must not ask
    /// the gateway for a node list on every Tab.
    #[test]
    fn a_verb_that_takes_no_node_is_not_offered_one() {
        for v in ["status", "discover", "seed", "nodes"] {
            assert!(!verb_takes_a_node(v), "`cluster {v}` does not take a node but is offered one");
        }
    }

    /// The guard that keeps it from going stale: EVERY node-first verb in
    /// the usage table answers true. A new verb inherits completion by
    /// existing, which is the whole point of deriving it.
    #[test]
    fn every_node_first_verb_in_the_usage_table_is_covered() {
        let mut checked = 0;
        for (words, syntax, _) in crate::usage::USAGE {
            if words.first() != Some(&"cluster") {
                continue;
            }
            let Some(verb) = words.get(1) else { continue };
            if syntax.starts_with("<node>") || syntax.starts_with("[<node>") {
                assert!(verb_takes_a_node(verb), "cluster {verb} is node-first and not covered");
                checked += 1;
            }
        }
        assert!(checked >= 14, "expected the usage table to hold many node-first verbs, found {checked}");
    }
}
