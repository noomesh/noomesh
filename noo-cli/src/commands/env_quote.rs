// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Writing and reading `KEY=value` lines in a node env file that a SHELL
//! sources, and the wrapper that refuses to start on a file it cannot parse.
//!
//! The Mac agent runs from `run-agent.sh`, which sources `~/noomesh/agent.env`
//! (launchd has no EnvironmentFile). An unquoted value with a space was split
//! by the shell: `NOO_DATA_ROOT=/Users/u/Library/Application Support/noo`
//! became an assignment to `/Users/u/Library/Application` plus a command named
//! `Support/noo`, the data-root variables were dropped, and the agent came up
//! declaring no data roots and refusing every placement (a Mac node,
//! 2026-10-06). Two fixes live here: values are quoted when they need it, and
//! the wrapper stops on a file that does not parse instead of starting on
//! defaults.

/// A value that needs no quoting: nothing a shell would split or expand.
fn is_plain(v: &str) -> bool {
    v.chars().all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c))
}

/// `v` as it must be written after `KEY=` so a shell reads back exactly `v`.
/// Plain values are returned unchanged (hex tokens, ordinary paths), so
/// existing files do not change. A value led by `$HOME` keeps that expansion
/// (the Mac env uses it on purpose) and is double-quoted with the rest
/// escaped; anything else is single-quoted.
pub(crate) fn env_quote(v: &str) -> String {
    if is_plain(v) {
        return v.to_string();
    }
    if let Some(rest) = v.strip_prefix("$HOME") {
        if rest.is_empty() || rest.starts_with('/') {
            if is_plain(rest) {
                return v.to_string();
            }
            let mut out = String::from("\"$HOME");
            for c in rest.chars() {
                if matches!(c, '"' | '\\' | '`' | '$') {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
            return out;
        }
    }
    format!("'{}'", v.replace('\'', "'\\''"))
}

/// The inverse for the values this module writes (and hand-written ones): a
/// sequence of single-quoted, double-quoted and bare segments, as a shell
/// would concatenate them. `$HOME` is not expanded here.
pub(crate) fn env_unquote(v: &str) -> String {
    let v = v.trim().trim_end_matches('\r');
    let mut out = String::new();
    let mut it = v.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\'' => {
                for d in it.by_ref() {
                    if d == '\'' {
                        break;
                    }
                    out.push(d);
                }
            }
            '"' => {
                while let Some(d) = it.next() {
                    match d {
                        '"' => break,
                        '\\' if matches!(it.peek(), Some('"' | '\\' | '`' | '$')) => out.push(it.next().unwrap()),
                        _ => out.push(d),
                    }
                }
            }
            '\\' => {
                if let Some(d) = it.next() {
                    out.push(d);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// The wrapper launchd runs: source `$HOME/noomesh/<env_file>`, then `exec`.
///
/// Sourcing is first tried in a throwaway `bash -c` under `set -e` (a separate
/// process, not a subshell: `set -e` is ignored inside anything `if`/`||`
/// tests, and an earlier version of this guard was silently inert for that
/// reason): a line the
/// shell cannot parse (an unquoted space, a stray `;`) makes a command out of
/// the tail of the value, which fails, and `source` ITSELF still returns the
/// last line's status — so only `set -e` sees it. On failure the wrapper
/// writes one line naming the file and bash's own complaint (which carries
/// the line number) and exits 78 (EX_CONFIG), never starting the program on
/// defaults.
pub(crate) fn run_wrapper(env_file: &str, comment: &str, exec_line: &str) -> String {
    format!(
        r#"#!/bin/bash
# {comment}
ENV_FILE="$HOME/noomesh/{env_file}"
[ -r "$ENV_FILE" ] || {{ echo "noo-run: $ENV_FILE is missing or unreadable — refusing to start" >&2; exit 78; }}
err=$(/bin/bash -c 'set -e; set -a; . "$1"' noo-run "$ENV_FILE" 2>&1 >/dev/null); rc=$?
if [ "$rc" -ne 0 ]; then
  echo "noo-run: $ENV_FILE did not parse (${{err%%$'\n'*}}) — quote values that contain spaces; refusing to start on defaults" >&2
  exit 78
fi
set -a; . "$ENV_FILE"; set +a
{exec_line}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn plain_values_are_untouched() {
        for v in ["", "/var/lib/noo", "0123abcDEF", "$HOME/noomesh/pki", "$HOME", "/Volumes/T7/noo"] {
            assert_eq!(env_quote(v), v);
        }
    }

    #[test]
    fn values_with_spaces_or_specials_are_quoted_and_round_trip() {
        for v in [
            "/Users/u/Library/Application Support/noo",
            "/Volumes/My Disk/noo",
            "a;b",
            "it's a path",
            "$HOME/My Disk/noo",
            "pa$$w\"rd `x`",
            "tab\there",
        ] {
            let q = env_quote(v);
            assert_ne!(q, v, "{v:?} must be quoted");
            let home_prefixed = v.starts_with("$HOME");
            let back = env_unquote(&q);
            assert_eq!(back, v, "{v:?} -> {q}");
            let _ = home_prefixed;
        }
        assert_eq!(env_quote("/a b"), "'/a b'");
        assert_eq!(env_quote("$HOME/a b"), "\"$HOME/a b\"");
    }

    /// Source a planted env file the way the wrapper does and print a var.
    fn sourced(env_text: &str, var: &str, home: &str) -> Option<String> {
        let d = std::env::temp_dir().join(format!("noo-envq-{}-{}", std::process::id(), env_text.len()));
        let _ = std::fs::create_dir_all(&d);
        let f = d.join("agent.env");
        std::fs::write(&f, env_text).ok()?;
        let out = Command::new("bash")
            .args(["-c", &format!("set -e; set -a; . '{}'; printf %s \"${var}\"", f.display())])
            .env("HOME", home)
            .output()
            .ok()?;
        let _ = std::fs::remove_dir_all(&d);
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).to_string())
    }

    #[test]
    fn a_data_root_with_a_space_survives_a_real_shell() {
        if Command::new("bash").arg("-c").arg("true").status().is_err() {
            return;
        }
        let root = "/Users/u/Library/Application Support/noo";
        let line = format!("NOO_DATA_ROOT={}\nMODELS_DIR={}\n", env_quote(root), env_quote(&format!("{root}/models")));
        assert_eq!(sourced(&line, "NOO_DATA_ROOT", "/Users/u").as_deref(), Some(root));
        assert_eq!(sourced(&line, "MODELS_DIR", "/Users/u").as_deref(), Some(&*format!("{root}/models")));
        // $HOME still expands inside the double quotes.
        let line = format!("NOO_DATA_ROOT={}\n", env_quote("$HOME/My Disk/noo"));
        assert_eq!(sourced(&line, "NOO_DATA_ROOT", "/Users/u").as_deref(), Some("/Users/u/My Disk/noo"));
        // The incident line, unquoted, is exactly what the shell refuses.
        assert_eq!(sourced(&format!("NOO_DATA_ROOT={root}\n"), "NOO_DATA_ROOT", "/Users/u"), None);
    }

    #[test]
    fn the_wrapper_text_guards_the_source_and_names_the_fix() {
        let s = run_wrapper("agent.env", "x", "exec true");
        assert!(s.starts_with("#!/bin/bash\n"));
        assert!(s.contains("set -e; set -a; . \"$1\""), "{s}");
        assert!(s.contains("exit 78"));
        assert!(s.contains("quote values that contain spaces"));
        // the real source comes only after the guard
        assert!(s.find("exit 78").unwrap() < s.rfind("set -a; . \"$ENV_FILE\"; set +a").unwrap());
    }

    /// Run the generated wrapper against a planted env file. The agent is
    /// replaced by a marker so we can tell whether it started.
    fn run_planted(env_text: &str) -> (i32, String, bool) {
        let d = std::env::temp_dir().join(format!("noo-wrap-{}-{}", std::process::id(), env_text.len()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("noomesh")).unwrap();
        std::fs::write(d.join("noomesh/agent.env"), env_text).unwrap();
        let marker = d.join("started");
        let script = run_wrapper("agent.env", "x", &format!("printf %s \"$NOO_DATA_ROOT\" > '{}'", marker.display()));
        let sh = d.join("run.sh");
        std::fs::write(&sh, script).unwrap();
        let out = Command::new("bash").arg(&sh).env("HOME", &d).output().unwrap();
        let started = marker.exists();
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        let _ = std::fs::remove_dir_all(&d);
        (out.status.code().unwrap_or(-1), err, started)
    }

    #[test]
    fn the_wrapper_refuses_to_start_on_an_env_file_that_does_not_parse() {
        if Command::new("bash").arg("-c").arg("true").status().is_err() {
            return;
        }
        let bad = "NODE_ID=a\nNOO_DATA_ROOT=/Users/u/Library/Application Support/noo\nMODELS_DIR=/x\n";
        let (code, err, started) = run_planted(bad);
        assert_eq!(code, 78, "{err}");
        assert!(!started, "the agent started on a file that did not parse");
        assert!(err.contains("did not parse") && err.contains("quote values that contain spaces"), "{err}");
        assert_eq!(err.lines().count(), 1, "one clear line, got: {err}");
        // The same file, quoted, starts with the root intact.
        let good = format!("NODE_ID=a\nNOO_DATA_ROOT={}\n", env_quote("/Users/u/Library/Application Support/noo"));
        let (code, err, started) = run_planted(&good);
        assert_eq!((code, started), (0, true), "{err}");
    }
}
