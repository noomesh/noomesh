// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Fall through to the Python CLI for commands not served natively.
//!
//! The Rust binary is meant to ship STANDALONE: on a host with no Python it
//! serves every native command (bootstrap + runtime control + provisioning)
//! and, for the handful of commands that still need the Python toolchain,
//! degrades with a clear message instead of a confusing error.
//!
//! Python-CLI resolution order:
//!   1. `$NOO_PY_CLI` — explicit path to a co-installed Python `noo`.
//!   2. a `noo-py` on PATH — a deliberately distinct name (NOT `noo`, which
//!      is this binary) for a side-by-side Python install.
//!   3. `<repo>/venv/bin/noo-py` (or legacy `noo`) — DERIVED from the repo root (dev machines
//!      only; absent on a shipped host, so it doesn't falsely resolve).
//! exec() replaces the process so streams, signals, and exit codes pass
//! through untouched.

use std::os::unix::process::CommandExt;
use std::path::PathBuf;

/// Commands that intentionally live only in the Python dev toolchain and are
/// NOT part of the standalone binary's contract. A developer runs these
/// inside the source tree, where Python exists. When the binary can't find
/// Python, these get a "not in standalone" message rather than being
/// reported as a generic failure.
///
/// EMPTY since 2026-09-03. Retired that day: `db revision` (alembic
/// autogenerate — dead since the mesh chain moved to SQL
/// revisions in gateway-rust/src/mesh_migrate.rs at 046; memory revisions
/// are authored in trellion), `test gen-stub/accept/status` (pytest
/// scaffolding for a package being retired) and `debug` (its memory-trace
/// endpoint was never ported and belongs to trellion's own CLI). The list
/// and its message path stay so a future dev-only command has a home.
const DEV_ONLY: &[&[&str]] = &[];

/// Commands that will NEVER be ported to the binary — the operations-vs-models
/// rule keeps them in the Python runtime:
/// in-process Python plugin loading. On a
/// host without Python these get a "requires the Python install" message,
/// not a generic failure. (`voice` left this list with WP-V: the gateway's
/// /api/voice/* routes proxy whisper/TTS. `models refresh` left with WP-R:
/// catalog rebuild + coordinator eval went native. `mcp tools` left with
/// WP-M: the hub owns the external MCP connections now. `loop` left with
/// WP-L: its transport was always thin HTTP, so it is native now —
/// pro-gated at build time, see commands/mod.rs.)
const PY_ONLY: &[&[&str]] = &[
    // `tui` left this list 2026-08-16: RETIRED outright (not ported) — the
    // web dashboard is the interactive UI and `noo chat` covers the
    // terminal. `noo tui` is a NATIVE entry that prints that pointer; the
    // module is archived at legacy/python-tui-reference/.
    // Python-PACKAGE plugin loading (~/.noo/plugins, imported in-process by
    // PluginManager) is inherently Python. No longer a blanket gate on the
    // group: `plugins list` is NATIVE since WP-PL (it lists executable
    // `noo-<name>` shims), so this entry is reached only for the bare group /
    // Unhandled fall-through — where the py-only message is still right.
    // Dev-only, trusted-code surface: these plugins execute
    // IN-PROCESS with no sandbox — the Python CLI prints a warning saying so.
    // Sandboxed extension code is a skill (`noo skills scaffold`); the
    // in-process tools/custom/ drop-in loader was deleted outright.
    &["plugins"],
];

/// First words of the DEV_ONLY/PY_ONLY entries. The dispatcher's plugin-shim
/// fallback (main.rs) uses this to keep a `noo-<word>` executable from
/// shadowing a Python-served group (`noo-voice` must not hijack `noo voice`).
pub fn is_gated_first_word(word: &str) -> bool {
    DEV_ONLY
        .iter()
        .chain(PY_ONLY.iter())
        .any(|words| words.first() == Some(&word))
}

/// True when `argv` starts with one of `entries`' word sequences (exact
/// word-prefix match, so single-word entries gate their whole subtree).
fn matches_words(entries: &[&[&str]], argv: &[String]) -> bool {
    entries.iter().any(|words| {
        argv.len() >= words.len() && words.iter().zip(argv).all(|(a, b)| a == b)
    })
}

fn is_dev_only(argv: &[String]) -> bool {
    matches_words(DEV_ONLY, argv)
}

fn is_py_only(argv: &[String]) -> bool {
    // No `onboard` special case remains: the wizard is native for EVERY
    // frontend — plain console, `--web` (embedded server, WP-W2), and
    // `--tui` (ratatui, WP-W1).
    matches_words(PY_ONLY, argv)
}

pub fn python_cli_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("NOO_PY_CLI") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }

    let self_exe = std::env::current_exe().and_then(|p| p.canonicalize()).ok();

    // A `noo-py` on PATH: an explicit side-by-side Python install (distinct
    // name so it never resolves back to this binary).
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("noo-py");
            if candidate.is_file() {
                if let Ok(c) = candidate.canonicalize() {
                    return Some(c);
                }
            }
        }
        // Legacy dev setup: a `noo` on PATH that isn't us (the venv shim).
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("noo");
            if !candidate.is_file() {
                continue;
            }
            let canonical = candidate.canonicalize().ok();
            if canonical.is_some() && canonical != self_exe {
                return canonical;
            }
        }
    }

    // Dev-machine convenience: <repo>/venv/bin/noo-py (or legacy noo),
    // DERIVED from the repo root rather than hardcoded — on a shipped host
    // there is no repo, so this yields nothing instead of pointing at a
    // stranger's home dir. Uses repo_root_STATIC (not repo_root) to avoid
    // mutual recursion: repo_root derives from python_cli_path, so calling
    // it here would loop.
    let venv_bin = crate::envfile::repo_root_static().join("venv/bin");
    for name in ["noo-py", "noo"] {
        let candidate = venv_bin.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Exec the Python CLI, or return a message explaining why it can't.
/// `argv` is the full original argument vector (used to tailor the message).
pub fn exec_python(argv: &[String]) -> Result<(), String> {
    match python_cli_path() {
        Some(py) => {
            // Only returns on failure.
            let err = std::process::Command::new(&py).args(argv).exec();
            Err(format!("failed to exec {}: {err}", py.display()))
        }
        None => Err(no_python_message(argv)),
    }
}

/// Why this command could not run, when no Python `noo` is installed.
///
/// A pure function so the wording is testable: the message is the ONLY thing
/// an operator on a python-less box gets, and it was wrong for a whole class
/// of commands (see the native-group arm).
pub(crate) fn no_python_message(argv: &[String]) -> String {
    if is_py_only(argv) {
        return format!(
            "`noo {}` requires the Python install (`pip install noomesh`) — \
             it is intentionally not part of the standalone binary \
             (interactive UIs, pro modules, and Python plugin \
             loading stay in Python). Install noomesh and set NOO_PY_CLI \
             to its `noo`, or put it on PATH as `noo-py`.",
            argv.join(" ")
        );
    }
    if is_dev_only(argv) {
        return format!(
            "`noo {}` is a developer command — it lives in the Python source \
             toolchain, not the standalone binary. Run it from a full source \
             checkout (where the venv is present), or set NOO_PY_CLI to a \
             Python `noo`.",
            argv.join(" ")
        );
    }
    // A NATIVE group with an unknown subcommand is not a missing Python
    // install, and saying so sends the operator to `pip install` for a group
    // this binary already serves. `noo security keys list` hit this:
    // `security` has 40-odd native subcommands, the verb is `service-key`,
    // and the answer named the GROUP rather than the word that was wrong.
    if let Some((group, _)) = native_group_misuse(argv) {
        let subs = crate::usage::subcommands_of(&group);
        // Name only the unknown token, not the whole command line (and its
        // arguments): `class` is not a subcommand of `noo cluster`.
        let unknown = argv.get(1).cloned().unwrap_or_else(|| argv.join(" "));
        return format!(
            "`{unknown}` is not a subcommand of `noo {group}` — which IS in this \
             binary, natively. Its subcommands: {}.",
            subs.join(", ")
        );
    }
    format!(
        "`noo {}` is not available in this standalone binary and no Python \
         `noo` was found. Set NOO_PY_CLI to a Python `noo`, or install one \
         as `noo-py` on PATH. (Native commands need no Python — try \
         `noo --help`.)",
        argv.first().map(String::as_str).unwrap_or("")
    )
}

/// A native group followed by a word or flag it does not own. Returns the
/// group and the nearest real subcommand, if any: `--verify` is the
/// subcommand `verify` typed as a flag; `verfy` is a plain typo.
pub(crate) fn native_group_misuse(argv: &[String]) -> Option<(String, Option<&'static str>)> {
    let group = argv.first().filter(|w| crate::usage::is_native_group(w))?;
    let subs = crate::usage::subcommands_of(group);
    let near = argv.get(1).and_then(|tok| {
        let bare = tok.trim_start_matches('-');
        if bare.is_empty() {
            return None;
        }
        subs.iter()
            .copied()
            .find(|s| *s == bare)
            .or_else(|| subs.iter().copied().find(|s| crate::edit_distance(s, bare) <= 2))
    });
    Some((group.clone(), near))
}

/// The remedy line for [`no_python_message`]. NOO_PY_CLI is the fallback for
/// commands that are not ported natively; for a native group it is wrong.
pub(crate) fn no_python_hint(argv: &[String]) -> String {
    if let Some((group, near)) = native_group_misuse(argv) {
        return match near {
            Some(sub) => format!("did you mean `noo {group} {sub}`?"),
            None => format!("`noo {group} --help` lists its subcommands"),
        };
    }
    "set NOO_PY_CLI to the Python `noo` entry point".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_typed_subcommand_suggests_the_subcommand() {
        let a = argv(&["cluster", "--verify"]);
        assert_eq!(no_python_hint(&a), "did you mean `noo cluster verify`?");
        let msg = no_python_message(&a);
        assert!(!msg.contains("NOO_PY_CLI"), "{msg}");
    }

    #[test]
    fn plain_typo_gets_nearest_match_and_native_group_never_hints_python() {
        assert_eq!(
            no_python_hint(&argv(&["cluster", "verfy"])),
            "did you mean `noo cluster verify`?"
        );
        let h = no_python_hint(&argv(&["cluster", "--zzzzzzzz"]));
        assert!(!h.contains("NOO_PY_CLI"), "{h}");
        assert!(no_python_hint(&argv(&["definitelynotacommand"])).contains("NOO_PY_CLI"));
    }

    #[test]
    fn the_unknown_subcommand_message_names_only_the_unknown_token() {
        let a = argv(&["cluster", "class", "set", "chat-default", "host3/vllm", "host6/ollama=gemma4:12b"]);
        let msg = no_python_message(&a);
        assert!(msg.starts_with("`class` is not a subcommand of `noo cluster`"), "{msg}");
        assert!(!msg.contains("chat-default") && !msg.contains("gemma4"), "{msg}");
    }

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    /// The message an operator on a python-less box gets is the only thing
    /// they get. For a native group it used to name the GROUP and prescribe
    /// NOO_PY_CLI — so `noo security keys list` (the verb is `service-key`)
    /// read as "`noo security` is not available in this standalone binary",
    /// which is false: `security` is native, and on the controller
    /// `noo security service-key list` prints the table straight away.
    #[test]
    fn a_native_group_is_never_called_unavailable() {
        let msg = no_python_message(&argv(&["security", "keys", "list"]));
        assert!(
            !msg.contains("not available in this standalone binary"),
            "a native group must not be reported as unavailable: {msg}"
        );
        assert!(
            !msg.contains("NOO_PY_CLI"),
            "nothing here needs Python; prescribing it sends the operator \
             to `pip install` for a group the binary already serves: {msg}"
        );
        assert!(msg.starts_with("`keys` is not a subcommand of `noo security`"), "name the word that was wrong: {msg}");
        assert!(msg.contains("service-key"), "list the real subcommands: {msg}");
    }

    /// The other arms must keep working — a genuinely unknown group, and a
    /// group that really does need Python, still say so.
    #[test]
    fn a_genuinely_absent_group_still_points_at_python() {
        let msg = no_python_message(&argv(&["definitelynotacommand", "x"]));
        assert!(msg.contains("not available in this standalone binary"), "{msg}");
        assert!(msg.contains("NOO_PY_CLI"), "{msg}");
    }

    #[test]
    fn a_py_only_command_still_names_the_python_install() {
        let msg = no_python_message(&argv(&["plugins"]));
        assert!(msg.contains("requires the Python install"), "{msg}");
    }

    #[test]
    fn dev_only_exact_matches() {
        // The list is empty since 2026-09-03: none of the retired commands
        // may get the friendly dev-only message any more — they are plain
        // unknown commands.
        assert!(!is_dev_only(&argv(&["db", "revision"])));
        assert!(!is_dev_only(&argv(&["test", "gen-stub"])));
        assert!(!is_dev_only(&argv(&["debug", "query", "abc"])));
    }

    #[test]
    fn non_dev_commands_are_not_gated() {
        // `cluster provision` and `test run` are part of the standalone
        // contract — they must NOT be flagged as developer-only.
        assert!(!is_dev_only(&argv(&["cluster", "provision"])));
        assert!(!is_dev_only(&argv(&["test", "run"])));
        // Went native in WP-TE (raw-registry endpoint) — must never regress
        // to the "developer-only" standalone message.
        assert!(!is_dev_only(&argv(&["tools", "export"])));
        assert!(!is_dev_only(&argv(&["health"])));
        assert!(!is_dev_only(&argv(&["db", "current"])));
        assert!(!is_dev_only(&argv(&[])));
    }

    #[test]
    fn dev_only_needs_full_words_not_partial() {
        // A shorter argv than the entry must not match (`test` alone is not a
        // dev-only entry — only specific `test <sub>` commands are).
        assert!(!is_dev_only(&argv(&["test"])));
        assert!(!is_dev_only(&argv(&["db"])));
    }

    #[test]
    fn py_only_single_word_entries_gate_their_subtree() {
        // `tui` was RETIRED 2026-08-16 — answered natively, never py-only.
        assert!(!is_py_only(&argv(&["tui"])));
        // `plugins` still gates its subtree HERE, but since WP-PL the native
        // `plugins list` intercepts before passthrough — this classification
        // only fires for the bare group word / an Unhandled fall-through,
        // where Python-package plugin loading is indeed what's being asked.
        assert!(is_py_only(&argv(&["plugins"])));
        assert!(is_py_only(&argv(&["plugins", "list"])));
        // WP-V: `voice` went native (thin HTTP to the gateway voice routes)
        // — it must NOT get the py-only message anymore.
        assert!(!is_py_only(&argv(&["voice"])));
        assert!(!is_py_only(&argv(&["voice", "transcribe", "a.wav"])));
        assert!(!is_py_only(&argv(&["voice", "status"])));
    }

    #[test]
    fn gated_first_words_cover_python_groups() {
        // The plugin-shim fallback must treat every gated group's first word
        // as reserved — including `mcp`/`db`/`test`, whose entries are
        // two-word (the FIRST word is what a shim could collide with).
        // (`voice`/`models`/`mcp`/`loop` left this list as WP-V/WP-R/WP-M/
        // WP-L made them NATIVE groups — native first words are reserved by
        // the builtins check, not this one. `tui` left it RETIRED 2026-08-16:
        // it is a native entry now, reserved as a builtin.)
        assert!(is_gated_first_word("plugins"), "plugins must be reserved from plugin shims");
        // `db`, `test` and `debug` left this list 2026-09-03 (authoring
        // commands retired; `db`/`test` are reserved as NATIVE first words).
        assert!(!is_gated_first_word("debug"));
        assert!(!is_gated_first_word("db"));
        assert!(!is_gated_first_word("frobnicate"));
        assert!(!is_gated_first_word("health"));
    }

    #[test]
    fn py_only_two_word_entries_are_exact_prefixes() {
        // Both former two-word entries went NATIVE (`mcp tools` WP-M,
        // `models refresh` WP-R) — neither may be flagged py-only, and
        // sibling subcommands stay ungated too.
        assert!(!is_py_only(&argv(&["mcp", "tools"])));
        assert!(!is_py_only(&argv(&["models", "refresh"])));
        assert!(!is_py_only(&argv(&["mcp"])));
        assert!(!is_py_only(&argv(&["models"])));
        assert!(!is_py_only(&argv(&["models", "list"])));
        // WP-R: `models refresh` went native — it must no longer be gated
        // as Python-only (a stale entry here would mislabel a native cmd).
        assert!(!is_py_only(&argv(&["models", "refresh"])));
    }

    #[test]
    fn onboard_is_fully_native_no_frontend_is_py_only() {
        // Every onboard frontend is native now: plain/--ci, --web (WP-W2's
        // embedded server), and --tui (WP-W1's ratatui frontend). None may
        // be classified as needing Python — a stale gate here would print
        // the py-only message instead of launching the native frontend.
        assert!(!is_py_only(&argv(&["onboard"])));
        assert!(!is_py_only(&argv(&["onboard", "--ci"])));
        assert!(!is_py_only(&argv(&["onboard", "--web"])));
        assert!(!is_py_only(&argv(&["onboard", "--web", "--port", "7080"])));
        assert!(!is_py_only(&argv(&["onboard", "--tui"])));
        assert!(!is_py_only(&argv(&["onboard", "--tui", "--dry-run"])));
        assert!(!is_py_only(&argv(&["onboard", "--reconfigure", "--tui"])));
    }

    #[test]
    fn py_only_and_dev_only_do_not_overlap() {
        // Each list carries its own message; an argv must never be both.
        for words in PY_ONLY {
            let a: Vec<String> = words.iter().map(|s| s.to_string()).collect();
            assert!(!is_dev_only(&a), "{words:?} is in both lists");
        }
        for words in DEV_ONLY {
            let a: Vec<String> = words.iter().map(|s| s.to_string()).collect();
            assert!(!is_py_only(&a), "{words:?} is in both lists");
        }
    }
}
