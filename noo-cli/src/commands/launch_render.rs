// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo config launch-render <section>` — hidden internal subcommand.
//!
//! The launcher (`scripts/noomesh-start.sh`, `lib-addons.sh`, `lib-config.sh`)
//! needs to read three sections of `noomesh.yaml` (`compose_env:`, `addons:`,
//! and the watched_folders/workspace mounts that build
//! `docker-compose.override.yml`) BEFORE any container exists. It used to
//! shell out to host `python3` + PyYAML for that, which is a second parser
//! for the same file — and on a newcomer host with neither Python nor
//! PyYAML installed, every `noo stack start` silently skipped compose_env,
//! the add-on map and the watched-folder mounts (2026-09-29 upgrade
//! rehearsal: `ModuleNotFoundError: No module named 'yaml'`).
//!
//! `noo` already parses `noomesh.yaml` with `serde_yaml` for its own
//! purposes (`envfile::load_yaml_compose_env`, `commands::addons`), and `noo`
//! is on every host that runs the launcher — it IS what invokes the
//! launcher. So this is not a new reader, it is the ONE reader, exposed to
//! the shell in the exact byte-for-byte shape the embedded Python blocks
//! used to produce, so `lib-config.sh` / `lib-addons.sh` / the override
//! regen in `noomesh-start.sh` do not have to change their parsing logic —
//! only where the text comes from.
//!
//! This is a hidden/internal command: an operator has no reason to type it,
//! it exists for the launcher scripts to call. It stays out of `noo --help`
//! and `noo config --help`'s subcommand list (see `HIDDEN_NATIVE` in
//! `main.rs`) but is still a real, tested, parity-proven NATIVE entry.

use serde_yaml::Value;

/// Collapse a (possibly multi-line) error message to one line. The shell
/// consumers of `compose-env`/`addons` are line-oriented; a stray
/// continuation line used to be parsed as `KEY=VALUE` and hit `export:
/// invalid variable name`, hiding the real error behind a confusing one.
fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Python `bool(value)` truthiness for a parsed YAML scalar/collection.
fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Sequence(s) => !s.is_empty(),
        Value::Mapping(m) => !m.is_empty(),
        Value::Tagged(t) => is_truthy(&t.value),
    }
}

/// `key.replace("_", "").isalnum()` — the Python rule for a valid flat
/// `compose_env` key.
fn is_env_key(k: &str) -> bool {
    let stripped: String = k.chars().filter(|&c| c != '_').collect();
    !stripped.is_empty() && stripped.chars().all(|c| c.is_alphanumeric())
}

/// Best-effort Python `repr()` of a YAML key that failed the key check —
/// covers the common scalar shapes (str, int, float, bool, null); a
/// mapping/sequence key is vanishingly rare in practice and falls back to
/// Rust's Debug form rather than a hand-rolled Python container repr.
fn py_repr(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
        _ => format!("{v:?}"),
    }
}

/// Python `str()` of a YAML scalar, for the `addons:` key (Python's `"%s" %
/// name` stringifies whatever the key is, even a non-string one).
fn py_str(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => format!("{v:?}"),
    }
}

/// `compose_env:` → `KEY=VALUE` / `!ERR <msg>` lines, byte-compatible with
/// the Python block `lib-config.sh::load_config` used to embed. Every
/// returned line ends in `\n`; the empty string means "nothing to export"
/// (no file, no section, or the section resolved to nothing).
pub fn render_compose_env(text: &str) -> String {
    let doc: Value = match serde_yaml::from_str(text) {
        Ok(d) => d,
        // Python's yaml.safe_load raised; collapse to ONE line so the
        // shell's line-oriented reader never mistakes a continuation line
        // for KEY=VALUE.
        Err(e) => return format!("!ERR {}\n", collapse(&e.to_string())),
    };
    let section = doc.get("compose_env");
    let map = match section {
        None | Some(Value::Null) => return String::new(),
        Some(Value::Mapping(m)) => m,
        Some(_) => return "!ERR compose_env must be a mapping of ENV_VAR: value\n".to_string(),
    };
    let mut out = String::new();
    for (k, v) in map {
        let key_str = match k {
            Value::String(s) => Some(s.clone()),
            _ => None,
        };
        let ok_key = key_str.as_deref().map(is_env_key).unwrap_or(false);
        if !ok_key {
            out.push_str(&format!("!ERR bad key {} — must be a plain ENV_VAR name\n", py_repr(k)));
            continue;
        }
        let key = key_str.unwrap();
        let value = match v {
            Value::Mapping(_) => {
                out.push_str(&format!(
                    "!ERR {key} is a dict, not a scalar — compose_env is a flat map of ENV_VAR: value\n"
                ));
                continue;
            }
            Value::Sequence(_) => {
                out.push_str(&format!(
                    "!ERR {key} is a list, not a scalar — compose_env is a flat map of ENV_VAR: value\n"
                ));
                continue;
            }
            Value::Null => String::new(),
            Value::Bool(b) => {
                if *b {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Tagged(t) => py_str(&t.value),
        };
        if value.contains('\n') {
            out.push_str(&format!("!ERR {key} has a multi-line value — not exportable\n"));
            continue;
        }
        out.push_str(&format!("{key}={value}\n"));
    }
    out
}

/// `addons:` → `name=1` / `name=0` lines, byte-compatible with
/// `lib-addons.sh`'s embedded Python block. A parse failure or a non-map
/// section prints nothing (the Python swallowed both silently).
pub fn render_addons(text: &str) -> String {
    let Ok(doc) = serde_yaml::from_str::<Value>(text) else {
        return String::new();
    };
    let Some(Value::Mapping(map)) = doc.get("addons") else {
        return String::new();
    };
    let mut out = String::new();
    for (k, v) in map {
        out.push_str(&py_str(k));
        out.push('=');
        out.push_str(if is_truthy(v) { "1" } else { "0" });
        out.push('\n');
    }
    out
}

/// `docker-compose.override.yml`'s full text, byte-compatible with the
/// Python block `noomesh-start.sh` (~line 93-133) used to embed. `Err` on a
/// YAML parse failure — the caller keeps the existing override file, as the
/// Python path did (`|| echo "override regen failed…"`).
pub fn render_override(text: &str) -> Result<String, String> {
    let doc: Value = serde_yaml::from_str(text).map_err(|e| collapse(&e.to_string()))?;

    let mut mounts: Vec<String> = Vec::new();
    if let Some(wf) = doc.get("watched_folders") {
        if wf.get("enabled").map(is_truthy).unwrap_or(false) {
            if let Some(Value::Sequence(folders)) = wf.get("folders") {
                for f in folders {
                    let host = f.get("host").and_then(Value::as_str);
                    let mount = f.get("mount").and_then(Value::as_str);
                    if let (Some(host), Some(mount)) = (host, mount) {
                        let writable = f.get("writable").map(is_truthy).unwrap_or(false);
                        let mode = if writable { "rw" } else { "ro" };
                        mounts.push(format!("{host}:{mount}:{mode}"));
                    }
                }
            }
        }
    }
    if let Some(ws) = doc.get("workspace") {
        if ws.get("enabled").map(is_truthy).unwrap_or(false) {
            let host = ws.get("host").and_then(Value::as_str);
            let mount = ws.get("mount").and_then(Value::as_str);
            if let (Some(host), Some(mount)) = (host, mount) {
                mounts.push(format!("{host}:{mount}:rw"));
            }
        }
    }

    let mut lines = vec![
        "# Auto-generated by noo stack start from noomesh.yaml — do not edit".to_string(),
        "# (watched_folders + workspace; regenerated on every start)".to_string(),
    ];
    if !mounts.is_empty() {
        lines.push("services:".to_string());
        for svc in ["gateway", "trellion"] {
            lines.push(format!("  {svc}:"));
            lines.push("    volumes:".to_string());
            for m in &mounts {
                lines.push(format!("      - {m}"));
            }
        }
    } else {
        lines.push("services: {}".to_string());
    }
    Ok(lines.join("\n") + "\n")
}

/// `systems`: the variable NAMES each declared system reads, one line per
/// system — `<name> <enabled_when or -> <password_env> <ddl_password_env>` —
/// for `lib-secrets.sh` `_declared_systems`, which builds the gateway's ONE
/// systems-secrets file from them. Names only: the values stay in the
/// launcher's shell. Parsed by `systems::parse_systems`, the same reader
/// `noo systems` and the pre-`up` credential check use. Not a replacement
/// for a python block, so it has no golden fixture.
pub(crate) fn render_systems(text: &str) -> Result<String, String> {
    let mut out = String::new();
    for (name, e) in crate::commands::systems::parse_systems(text)? {
        out.push_str(&format!(
            "{name} {} {} {}\n",
            e.enabled_when.as_deref().unwrap_or("-"),
            e.password_env,
            e.ddl_password_env
        ));
    }
    Ok(out)
}

/// `noo config launch-render <section>`. Reads `<repo_root>/noomesh.yaml`;
/// a missing file prints nothing and exits 0 for every section — same as
/// the Python blocks it replaces, which each guarded on `-f noomesh.yaml`
/// before ever spawning.
pub fn run(section: &str, file: Option<&std::path::Path>) -> i32 {
    let path = match file {
        Some(f) => f.to_path_buf(),
        None => crate::envfile::repo_root().join("noomesh.yaml"),
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return 0,
    };
    match section {
        "compose-env" => {
            print!("{}", render_compose_env(&text));
            0
        }
        "addons" => {
            print!("{}", render_addons(&text));
            0
        }
        "override" => match render_override(&text) {
            Ok(out) => {
                print!("{out}");
                0
            }
            Err(e) => {
                eprintln!("noo config launch-render override: {e}");
                1
            }
        },
        "systems" => match render_systems(&text) {
            Ok(out) => {
                print!("{out}");
                0
            }
            Err(e) => {
                eprintln!("noo config launch-render systems: {e}");
                65
            }
        },
        other => {
            eprintln!(
                "noo config launch-render: unknown section '{other}' (want: compose-env | addons | override | systems)"
            );
            64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── systems ──────────────────────────────────────────────────────

    #[test]
    fn systems_renders_the_variable_names_never_values() {
        let yaml = "systems:\n  example_addon:\n    role: noo_example_addon\n    ddl_role: noo_example_addon_ddl\n    schema: example_addon\n    enabled_when: NOO_EXAMPLE_ADDON_ENABLED\n    password_env: NOO_EXAMPLE_ADDON_DB_PASSWORD\n    ddl_password_env: NOO_EXAMPLE_ADDON_DDL_PASSWORD\n  trellion:\n    role: noo_trellion\n    ddl_role: noo_trellion_ddl\n    schema: trellion\n    password_env: NOO_TRELLION_DB_PASSWORD\n    ddl_password_env: NOO_TRELLION_DDL_PASSWORD\n";
        assert_eq!(
            render_systems(yaml).unwrap(),
            "example_addon NOO_EXAMPLE_ADDON_ENABLED NOO_EXAMPLE_ADDON_DB_PASSWORD NOO_EXAMPLE_ADDON_DDL_PASSWORD\n\
             trellion - NOO_TRELLION_DB_PASSWORD NOO_TRELLION_DDL_PASSWORD\n"
        );
        assert_eq!(render_systems("addons: {}\n").unwrap(), "");
        assert!(render_systems("systems:\n  x:\n    role: r\n").is_err());
    }

    // ── compose-env ──────────────────────────────────────────────────

    #[test]
    fn compose_env_basic_scalars() {
        let y = "compose_env:\n  NODE_ID: noo-controller\n  PORT: 8080\n  RATIO: 1.5\n";
        let out = render_compose_env(y);
        assert_eq!(out, "NODE_ID=noo-controller\nPORT=8080\nRATIO=1.5\n");
    }

    #[test]
    fn compose_env_bool_and_null() {
        let y = "compose_env:\n  FLAG_ON: true\n  FLAG_OFF: false\n  EMPTY: null\n";
        let out = render_compose_env(y);
        assert_eq!(out, "FLAG_ON=true\nFLAG_OFF=false\nEMPTY=\n");
    }

    #[test]
    fn compose_env_no_section_is_empty() {
        assert_eq!(render_compose_env("cluster:\n  id: x\n"), "");
        assert_eq!(render_compose_env(""), "");
    }

    #[test]
    fn compose_env_section_not_a_mapping() {
        let y = "compose_env: [1, 2]\n";
        assert_eq!(
            render_compose_env(y),
            "!ERR compose_env must be a mapping of ENV_VAR: value\n"
        );
    }

    #[test]
    fn compose_env_nested_dict_value() {
        let y = "compose_env:\n  FOO:\n    bar: baz\n";
        assert_eq!(
            render_compose_env(y),
            "!ERR FOO is a dict, not a scalar — compose_env is a flat map of ENV_VAR: value\n"
        );
    }

    #[test]
    fn compose_env_nested_list_value() {
        let y = "compose_env:\n  FOO:\n    - bar\n    - baz\n";
        assert_eq!(
            render_compose_env(y),
            "!ERR FOO is a list, not a scalar — compose_env is a flat map of ENV_VAR: value\n"
        );
    }

    #[test]
    fn compose_env_bad_key() {
        let y = "compose_env:\n  \"bad key!\": x\n";
        assert_eq!(
            render_compose_env(y),
            "!ERR bad key 'bad key!' — must be a plain ENV_VAR name\n"
        );
    }

    #[test]
    fn compose_env_multiline_value() {
        let y = "compose_env:\n  FOO: |\n    line1\n    line2\n";
        assert_eq!(
            render_compose_env(y),
            "!ERR FOO has a multi-line value — not exportable\n"
        );
    }

    #[test]
    fn compose_env_parse_failure_is_one_line() {
        // Unterminated flow mapping — a genuine YAML syntax error.
        let y = "compose_env: {NODE_ID: \n";
        let out = render_compose_env(y);
        assert!(out.starts_with("!ERR "), "{out:?}");
        assert_eq!(out.lines().count(), 1, "{out:?}");
    }

    // ── addons ────────────────────────────────────────────────────────

    #[test]
    fn addons_truthiness() {
        let y = "addons:\n  a: true\n  b: false\n  c: 1\n  d: 0\n  e: \"\"\n  f: yes\n  g: null\n";
        let out = render_addons(y);
        assert_eq!(out, "a=1\nb=0\nc=1\nd=0\ne=0\nf=1\ng=0\n");
    }

    #[test]
    fn addons_missing_section_prints_nothing() {
        assert_eq!(render_addons("cluster:\n  id: x\n"), "");
    }

    #[test]
    fn addons_parse_error_prints_nothing() {
        assert_eq!(render_addons("addons: {a: \n"), "");
    }

    #[test]
    fn addons_no_section_produces_no_lines_ever_when_absent() {
        let out = render_addons("compose_env:\n  X: 1\n");
        assert_eq!(out, "");
    }

    // ── override ──────────────────────────────────────────────────────

    #[test]
    fn override_no_folders_no_workspace() {
        let out = render_override("cluster:\n  id: x\n").unwrap();
        assert!(out.contains("services: {}"), "{out}");
        assert!(!out.contains("volumes"));
    }

    #[test]
    fn override_with_readonly_and_writable_folder() {
        let y = "\
watched_folders:
  enabled: true
  folders:
    - host: /home/op/docs
      mount: /data/docs
    - host: /home/op/scratch
      mount: /data/scratch
      writable: true
";
        let out = render_override(y).unwrap();
        assert!(out.contains("services:"), "{out}");
        assert!(out.contains("  gateway:"), "{out}");
        assert!(out.contains("  trellion:"), "{out}");
        assert!(out.contains("      - /home/op/docs:/data/docs:ro"), "{out}");
        assert!(out.contains("      - /home/op/scratch:/data/scratch:rw"), "{out}");
    }

    #[test]
    fn override_workspace_is_always_rw() {
        let y = "\
workspace:
  enabled: true
  host: /home/op/ws
  mount: /workspace
";
        let out = render_override(y).unwrap();
        assert!(out.contains("      - /home/op/ws:/workspace:rw"), "{out}");
    }

    #[test]
    fn override_disabled_watched_folders_contributes_nothing() {
        let y = "\
watched_folders:
  enabled: false
  folders:
    - host: /home/op/docs
      mount: /data/docs
";
        let out = render_override(y).unwrap();
        assert!(out.contains("services: {}"), "{out}");
    }

    #[test]
    fn override_parse_error_is_err() {
        let err = render_override("watched_folders: {enabled: \n").unwrap_err();
        assert!(!err.is_empty());
        assert_eq!(err.lines().count(), 1);
    }

    #[test]
    fn run_no_file_prints_nothing_exit_zero() {
        // The launcher passes the file it would have read; a missing one is
        // "nothing declared", not an error — same as the python readers.
        let missing = std::env::temp_dir()
            .join(format!("noo-launch-render-test-{}", std::process::id()))
            .join("noomesh.yaml");
        assert!(!missing.exists());
        assert_eq!(run("compose-env", Some(&missing)), 0);
        assert_eq!(run("addons", Some(&missing)), 0);
        assert_eq!(run("override", Some(&missing)), 0);
    }

    #[test]
    fn run_reads_the_file_it_is_given_not_the_repo_root() {
        let dir = std::env::temp_dir().join(format!("noo-launch-render-given-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("noomesh.yaml");
        std::fs::write(&f, "compose_env:\n  NOO_TEST_GIVEN: \"1\"\n").unwrap();
        // The renderer is pure over the text; run() must pick up THIS file.
        let text = std::fs::read_to_string(&f).unwrap();
        assert_eq!(render_compose_env(&text), "NOO_TEST_GIVEN=1\n");
        assert_eq!(run("compose-env", Some(&f)), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Golden-file parity: the Rust side of the byte-compatibility proof.
///
/// `tests/fixtures/launch_render/<case>/noomesh.yaml` plus its committed
/// `compose-env.out` / `addons.out` / `override.out` (or `override.err`)
/// are the SAME goldens `tests/test_launch_render_parity.py` runs the
/// python3 fallback blocks against. Two independent readers (this one,
/// serde_yaml; that one, PyYAML) converging on one committed expectation
/// is the actual parity proof — neither test needs the other language
/// built or installed, which is why the original binary-vs-python parity
/// test SKIPPED for all 18 cases in PR #551's own CI run (the pytest job
/// never builds noo-cli/target/debug/noo).
///
/// The fixtures live under the repo root, not under noo-cli/, so this
/// walks up from CARGO_MANIFEST_DIR. The noo-cli CI job checks out the
/// whole monorepo with a plain `actions/checkout@v4` (no sparse-checkout
/// is configured for it in .github/workflows/ci.yml), so this relative
/// path resolves there exactly as it does locally.
#[cfg(test)]
mod golden {
    use super::*;
    use std::path::PathBuf;

    // See tests/fixtures/launch_render/regen.py's docstring: PyYAML's
    // syntax-error message embeds the absolute path of the file it read,
    // so this one case has no byte-identical compose-env.out golden across
    // machines. Both this module and test_launch_render_parity.py
    // special-case it by name instead of a byte comparison.
    const SYNTAX_ERROR_CASES: &[&str] = &["yaml_syntax_error"];

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures/launch_render"))
    }

    fn cases() -> Vec<PathBuf> {
        let dir = fixtures_dir();
        let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot read fixtures dir {}: {e}", dir.display()))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        out.sort();
        out
    }

    #[test]
    fn golden_case_count_is_not_vacuous() {
        // An empty/broken glob (wrong path, fixtures not checked out) must
        // not silently pass every test below.
        let n = cases().len();
        assert!(
            n >= 10,
            "expected >= 10 launch_render golden cases under {}, found {n}",
            fixtures_dir().display()
        );
    }

    #[test]
    fn compose_env_matches_golden() {
        for case in cases() {
            let name = case.file_name().unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(case.join("noomesh.yaml")).unwrap();
            let out = render_compose_env(&text);

            if SYNTAX_ERROR_CASES.contains(&name.as_str()) {
                assert!(out.starts_with("!ERR "), "[{name}] {out:?}");
                assert_eq!(out.lines().count(), 1, "[{name}] {out:?}");
                continue;
            }

            let golden_path = case.join("compose-env.out");
            assert!(golden_path.exists(), "[{name}] missing compose-env.out golden");
            let golden = std::fs::read_to_string(&golden_path).unwrap();
            assert_eq!(out, golden, "[{name}] compose-env rust output != golden");
        }
    }

    #[test]
    fn addons_matches_golden() {
        for case in cases() {
            let name = case.file_name().unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(case.join("noomesh.yaml")).unwrap();
            let out = render_addons(&text);
            let golden_path = case.join("addons.out");
            assert!(golden_path.exists(), "[{name}] missing addons.out golden");
            let golden = std::fs::read_to_string(&golden_path).unwrap();
            assert_eq!(out, golden, "[{name}] addons rust output != golden");
        }
    }

    #[test]
    fn override_matches_golden() {
        for case in cases() {
            let name = case.file_name().unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(case.join("noomesh.yaml")).unwrap();
            let result = render_override(&text);
            let err_golden = case.join("override.err");
            let out_golden = case.join("override.out");
            if err_golden.exists() {
                assert!(
                    result.is_err(),
                    "[{name}] expected render_override to Err (override.err present) but got: {result:?}"
                );
                let contents = std::fs::read_to_string(&err_golden).unwrap();
                assert_eq!(contents.trim(), "fail");
            } else {
                let out = result.unwrap_or_else(|e| panic!("[{name}] unexpected Err: {e}"));
                assert!(out_golden.exists(), "[{name}] missing override.out golden");
                let golden = std::fs::read_to_string(&out_golden).unwrap();
                assert_eq!(out, golden, "[{name}] override rust output != golden");
            }
        }
    }
}
