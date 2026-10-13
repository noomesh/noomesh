// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo skills …` — containerized skill registry.
//!
//! `list`/`info` are a LOCAL filesystem scan of `<repo>/skills/builtins/` and
//! the user dir (`$NOO_SKILLS_DIR` | `~/.noo/skills`), byte-for-byte the
//! source `SkillRegistry` reads (glob `*/manifest.yml`, parse YAML). This is
//! deliberately NOT the gateway's `/api/skills/list` route: on a normal host
//! the gateway container has no `skills/` mounted and returns an empty list,
//! while the Python CLI reads the repo registry — so the gateway view
//! disagrees (0 vs 3 skills here). The local scan matches Python exactly and
//! works when the gateway is down.
//!
//! `run NAME JSON [--node N]`: posts to the gateway
//! (`POST /api/skills/{name}/run`), which builds the container spec from the
//! manifest and sends it to a node agent's `POST /api/skills/run` with the
//! controller's certificate. `--gateway`/`-g` is still accepted; it is the
//! only path now.
//!
//! There used to be a "local executor" that POSTed the spec straight to
//! `NOO_NODE_AGENT_URL` (default `https://localhost:8081`) with the static
//! `NOO_NODE_AGENT_TOKEN`. It could not have worked: node agents require a
//! client certificate at the TLS handshake and this client presented none,
//! nor did it trust the cluster CA. Agents now admit only the controller's
//! leaf, and the static token is being retired, so the path was deleted
//!  instead of being given a credential.
//!
//! `scaffold NAME [--dir DIR]`: purely local generation of a
//! skill skeleton — the sanctioned replacement for the deleted in-process
//! `tools/custom/` drop-in loader. See [`skills_scaffold`].

use std::path::PathBuf;

use super::truncate;
use crate::ui::{self, Col};
use crate::envfile::repo_root;
use crate::http::post_json;
use crate::{Globals, Unhandled};

/// Skill search dirs, in Python's order: repo builtins, then the user dir
/// (later entries override earlier ones by name).
fn skill_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![repo_root().join("skills").join("builtins")];
    let user = std::env::var("NOO_SKILLS_DIR").map(PathBuf::from).unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        PathBuf::from(home).join(".noo").join("skills")
    });
    dirs.push(user);
    dirs
}

/// Scan the skill dirs → `(name, manifest_value, skill_dir)`, user dir
/// overriding builtins by name (parity with the registry's name-keyed dict).
fn scan_skills() -> Vec<(String, serde_json::Value, PathBuf)> {
    let mut out: Vec<(String, serde_json::Value, PathBuf)> = Vec::new();
    for dir in skill_dirs() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let manifest_path = path.join("manifest.yml");
            if !manifest_path.is_file() {
                continue;
            }
            let contents = match std::fs::read_to_string(&manifest_path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let manifest: serde_json::Value = match serde_yaml::from_str(&contents) {
                Ok(v) => v,
                Err(_) => continue, // skip unparseable, like the registry's try/except
            };
            let name = manifest["name"]
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| entry.file_name().to_string_lossy().into_owned());
            // user dir overrides builtins by name
            if let Some(slot) = out.iter_mut().find(|(n, _, _)| *n == name) {
                *slot = (name, manifest, path);
            } else {
                out.push((name, manifest, path));
            }
        }
    }
    out
}

/// `noo skills list` — local registry scan.
pub fn skills_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let skills = scan_skills();

    if g.json {
        let arr: Vec<serde_json::Value> = skills
            .iter()
            .map(|(name, m, dir)| {
                serde_json::json!({
                    "name": name,
                    // A manifest with no `version`/`author` used to be
                    // reported as version "0.0.1" by "noo-builtin" — a
                    // fabricated provenance claim for a skill that declared
                    // neither. Missing means unknown.
                    "version": m["version"].as_str().unwrap_or("unknown"),
                    "description": m["description"].as_str().unwrap_or(""),
                    "author": m["author"].as_str().unwrap_or("unknown"),
                    "gpu": m["container"]["gpu"].as_bool().unwrap_or(false),
                    "image": m["container"]["image"].as_str().unwrap_or(""),
                    "skill_dir": dir.to_string_lossy(),
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "skills": arr }));
        return Ok(0);
    }

    if skills.is_empty() {
        println!("{}", ui::muted("no skills"));
        return Ok(0);
    }
    println!("{}", ui::header("skills", Some(&format!("{} installed", skills.len()))));
    println!();
    let rows: Vec<Vec<String>> = skills
        .iter()
        .map(|(name, m, _)| {
            vec![
                truncate(name, 20),
                ui::muted(&truncate(m["version"].as_str().unwrap_or("?"), 8)),
                truncate(m["author"].as_str().unwrap_or(""), 14),
                if m["container"]["gpu"].as_bool().unwrap_or(false) { "gpu".into() } else { String::new() },
                ui::muted(&truncate(m["container"]["image"].as_str().unwrap_or(""), 22)),
                truncate(m["description"].as_str().unwrap_or(""), 50),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left("name"), Col::left("version"), Col::left("author"), Col::left("gpu"), Col::left("image"), Col::left("description")],
            &rows,
        )
    );
    Ok(0)
}

/// `noo skills info NAME` — full manifest for one skill (local scan).
pub fn skills_info(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [name] = args else { return Err(Unhandled) };
    if name.starts_with('-') {
        return Err(Unhandled);
    }
    let skills = scan_skills();
    let Some((sname, m, dir)) = skills.iter().find(|(n, _, _)| n == name) else {
        crate::output::fail(
            g.json,
            crate::output::ExitCode::Generic,
            "not_found",
            &format!("skill not found: {name}"),
            None,
        );
    };

    if g.json {
        let mut obj = m.clone();
        obj["skill_dir"] = serde_json::Value::String(dir.to_string_lossy().into_owned());
        println!("{obj}");
        return Ok(0);
    }

    println!("{}", ui::header(sname, Some(&format!("v{}", m["version"].as_str().unwrap_or("?")))));
    let mut rows: Vec<(&str, String)> = vec![("author", m["author"].as_str().unwrap_or(ui::dash()).to_string())];
    if let Some(d) = m["description"].as_str() {
        if !d.is_empty() {
            rows.push(("description", d.to_string()));
        }
    }
    rows.push(("directory", ui::muted(&dir.to_string_lossy())));
    print!("{}", ui::kv(&rows));

    let c = &m["container"];
    if c.is_object() {
        println!("{}", ui::section("container"));
        let mut rows: Vec<(&str, String)> = Vec::new();
        if let Some(img) = c["image"].as_str() {
            rows.push(("image", img.to_string()));
        }
        if let Some(cmd) = c["command"].as_array() {
            let joined = cmd.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(" ");
            rows.push(("command", ui::cmd(&joined)));
        }
        if let Some(t) = c["timeout"].as_u64() {
            rows.push(("timeout", format!("{t}s")));
        }
        if let Some(mem) = c["memory_limit"].as_str() {
            rows.push(("memory", mem.to_string()));
        }
        if let Some(n) = c["network"].as_str() {
            rows.push(("network", n.to_string()));
        }
        rows.push(("gpu", if c["gpu"].as_bool().unwrap_or(false) { "yes".into() } else { "no".into() }));
        print!("{}", ui::kv(&rows));
    }

    let p = &m["permissions"];
    if let Some(map) = p.as_object() {
        if !map.is_empty() {
            println!("{}", ui::section("permissions"));
            // Unwrap JSON strings so values print bare (none, restricted)
            // instead of quoted, matching the Python renderer.
            let rows: Vec<(&str, String)> = map
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))
                .collect();
            print!("{}", ui::kv(&rows));
        }
    }

    render_io(&m["inputs"], "inputs");
    render_io(&m["outputs"], "outputs");
    Ok(0)
}

/// Render a manifest inputs/outputs section — a mapping of
/// `name → {type,required,description}` (or, tolerantly, a list of params).
fn render_io(v: &serde_json::Value, label: &str) {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let req = |d: &serde_json::Value| -> String {
        if d["required"].as_bool().unwrap_or(false) { ui::warn("required") } else { String::new() }
    };
    if let Some(map) = v.as_object() {
        for (name, def) in map {
            rows.push(vec![
                name.clone(),
                def["type"].as_str().unwrap_or("?").to_string(),
                req(def),
                ui::muted(def["description"].as_str().unwrap_or("")),
            ]);
        }
    } else if let Some(arr) = v.as_array() {
        for p in arr {
            rows.push(vec![
                p["name"].as_str().unwrap_or("?").to_string(),
                p["type"].as_str().unwrap_or("?").to_string(),
                req(p),
                ui::muted(p["description"].as_str().unwrap_or("")),
            ]);
        }
    }
    if rows.is_empty() {
        return;
    }
    println!("{}", ui::section(label));
    print!("{}", ui::table(&[Col::left("name"), Col::left("type"), Col::left(""), Col::left("")], &rows));
}

// ---------------------------------------------------------------------------
// Scaffold
// ---------------------------------------------------------------------------

/// Skill names are directory + container-name material: lowercase snake,
/// starting with a letter (the shape every builtin uses).
fn valid_skill_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// manifest.yml skeleton — same field set as the builtins
/// (`skills/builtins/*/manifest.yml`), tightest defaults (no network, no
/// filesystem, no shell); authors open up only what the skill needs.
fn scaffold_manifest(name: &str) -> String {
    format!(
        "name: {name}\n\
         version: 0.1.0\n\
         description: TODO — one line on what this skill does.\n\
         author: TODO\n\
         \n\
         inputs:\n\
         \x20 text:\n\
         \x20   type: string\n\
         \x20   required: true\n\
         \x20   description: TODO — describe this input\n\
         \n\
         outputs:\n\
         \x20 result:\n\
         \x20   type: string\n\
         \x20   description: TODO — describe this output\n\
         \n\
         container:\n\
         \x20 image: noo-sandbox-base:latest\n\
         \x20 command: [\"python\", \"/skill/run.py\"]\n\
         \x20 timeout: 60\n\
         \x20 memory_limit: 256m\n\
         \x20 network: none\n\
         \x20 gpu: false\n\
         \n\
         permissions:\n\
         \x20 filesystem: none\n\
         \x20 network: none\n\
         \x20 shell: false\n"
    )
}

/// run.py skeleton — the SKILL_INPUT → stdout-JSON contract every builtin
/// follows (see the worked example, `skills/examples/hello_greeter/run.py`).
fn scaffold_run_py(name: &str) -> String {
    format!(
        "#!/usr/bin/env python3\n\
         \"\"\"{name} sandbox capability.\n\
         \n\
         Contract (see manifest.yml):\n\
         \x20 input  (env SKILL_INPUT, JSON): {{text: str (required)}}\n\
         \x20 output (stdout, JSON):          {{result: str}}\n\
         \n\
         Errors go to stderr with a non-zero exit code; the sandbox executor\n\
         turns a non-zero exit into a failed SandboxResult. Worked example:\n\
         skills/examples/hello_greeter/ in the repo.\n\
         \"\"\"\n\
         import json\n\
         import os\n\
         import sys\n\
         \n\
         \n\
         def main() -> int:\n\
         \x20   try:\n\
         \x20       inputs = json.loads(os.environ.get(\"SKILL_INPUT\", \"{{}}\"))\n\
         \x20   except json.JSONDecodeError as e:\n\
         \x20       print(f\"invalid SKILL_INPUT JSON: {{e}}\", file=sys.stderr)\n\
         \x20       return 2\n\
         \n\
         \x20   text = inputs.get(\"text\")\n\
         \x20   if not isinstance(text, str) or not text.strip():\n\
         \x20       print(\"missing required input 'text'\", file=sys.stderr)\n\
         \x20       return 2\n\
         \n\
         \x20   # TODO: your skill logic here.\n\
         \x20   json.dump({{\"result\": text}}, sys.stdout)\n\
         \x20   return 0\n\
         \n\
         \n\
         if __name__ == \"__main__\":\n\
         \x20   sys.exit(main())\n"
    )
}

/// Write the skeleton into `parent/NAME`. Pure over its inputs (no env), so
/// the unit tests drive it with temp dirs. Errors are returned as strings.
fn scaffold_into(parent: &std::path::Path, name: &str) -> Result<PathBuf, String> {
    if !valid_skill_name(name) {
        return Err(format!(
            "invalid skill name '{name}': use lowercase letters, digits and underscores, \
             starting with a letter (e.g. my_skill)"
        ));
    }
    let dir = parent.join(name);
    if dir.exists() {
        return Err(format!("already exists: {}", dir.display()));
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    for (fname, body) in [
        ("manifest.yml", scaffold_manifest(name)),
        ("run.py", scaffold_run_py(name)),
    ] {
        let p = dir.join(fname);
        std::fs::write(&p, body).map_err(|e| format!("cannot write {}: {e}", p.display()))?;
    }
    Ok(dir)
}

/// `noo skills scaffold NAME [--dir DIR]` — generate a sandboxed-skill
/// skeleton (manifest.yml + run.py) exactly in the layout the registry scans
/// and the sandbox executes. This is the sanctioned "drop a file, get a
/// tool" gesture: the in-process `tools/custom/` plugin loader was deleted
/// in an earlier release because it ran extension code inside the worker pool with
/// no boundary. Default target is the user skills dir
/// (`$NOO_SKILLS_DIR` | `~/.noo/skills`), where `noo skills list/run` pick
/// it up immediately.
pub fn skills_scaffold(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut name: Option<&str> = None;
    let mut dir: Option<String> = None;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dir" | "-d" => dir = it.next().cloned(),
            s if s.starts_with('-') => return Err(Unhandled),
            s => {
                if name.is_none() {
                    name = Some(s);
                } else {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(name) = name else { return Err(Unhandled) };

    // Default parent: the USER dir from the registry's search order — never
    // the repo builtins (those are shipped code, not operator drop-ins).
    let parent = match &dir {
        Some(d) => PathBuf::from(d),
        None => skill_dirs().pop().expect("skill_dirs always has the user dir"),
    };

    match scaffold_into(&parent, name) {
        Ok(created) => {
            if g.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "created": true,
                        "skill_dir": created.to_string_lossy(),
                        "files": ["manifest.yml", "run.py"],
                    })
                );
            } else {
                // The created path is the captured value; the file guide is narration.
                ui::done(&format!("created {}", created.display()));
                ui::value(&created.display().to_string());
                if !ui::quiet() {
                    print!(
                        "{}",
                        ui::kv(&[
                            ("manifest.yml", ui::muted("fill in description/author, inputs/outputs")),
                            ("run.py", ui::muted("SKILL_INPUT (env, JSON) in, JSON on stdout out")),
                        ])
                    );
                    println!("{}", ui::note("worked example: skills/examples/hello_greeter/"));
                }
                let run_cmd = format!("noo skills run {name} '{{\"text\": \"hello\"}}'");
                ui::guide(&[
                    (run_cmd.as_str(), "runs the scaffold in the sandbox with a sample input"),
                    ("noo skills list", "confirms the new skill is discoverable"),
                ]);
            }
            Ok(0)
        }
        Err(msg) => crate::output::fail(
            g.json,
            crate::output::ExitCode::Generic,
            "scaffold_failed",
            &msg,
            None,
        ),
    }
}

/// `noo skills run NAME JSON [--node/-n NODE]` →
/// POST {gateway}/api/skills/{name}/run. `--gateway`/`-g` is accepted and
/// changes nothing: the gateway is the only path.
pub fn skills_run(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut name: Option<&str> = None;
    let mut input_json: Option<&str> = None;
    let mut node: Option<String> = None;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" => {}
            "--node" | "-n" => node = it.next().cloned(),
            s if s.starts_with('-') => return Err(Unhandled),
            s => {
                if name.is_none() {
                    name = Some(s);
                } else if input_json.is_none() {
                    input_json = Some(s);
                } else {
                    return Err(Unhandled);
                }
            }
        }
    }

    let (Some(name), Some(input_json)) = (name, input_json) else {
        return Err(Unhandled);
    };

    let inputs: serde_json::Value = match serde_json::from_str(input_json) {
        Ok(v) => v,
        Err(e) => crate::output::fail(
            g.json,
            crate::output::ExitCode::Generic,
            "bad_input",
            &format!("invalid JSON input: {e}"),
            None,
        ),
    };

    let mut payload = serde_json::json!({ "inputs": inputs });
    if let Some(n) = &node {
        payload["node_id"] = serde_json::Value::String(n.clone());
    }

    let body = post_json(g, &format!("/api/skills/{}/run", super::urlencode(name)), &payload, true, 120);
    if g.json {
        println!("{body}");
        return Ok(if body["success"].as_bool().unwrap_or(false) { 0 } else { 1 });
    }
    if body["success"].as_bool().unwrap_or(false) {
        // The skill's output is the data (stdout); the timing is narration.
        ui::done(&format!("skill completed in {:.0}ms", body["duration_ms"].as_f64().unwrap_or(0.0)));
        let out = &body["output"];
        if !out.is_null() {
            // The skill's output is the captured value.
            ui::value(&serde_json::to_string_pretty(out).unwrap_or_else(|_| out.to_string()));
        }
        let info_cmd = format!("noo skills info {name}");
        ui::guide(&[
            (info_cmd.as_str(), "the skill's inputs and outputs, for the next call"),
            ("noo skills list", "everything else you can run"),
        ]);
        Ok(0)
    } else {
        let info_cmd = format!("noo skills info {name}");
        ui::failed(&format!("skill failed: {}", body["error"].as_str().unwrap_or("unknown")), Some(&info_cmd));
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("noo-cli-skills-tests-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn skill_name_validation() {
        assert!(valid_skill_name("my_skill"));
        assert!(valid_skill_name("s2"));
        assert!(!valid_skill_name(""));
        assert!(!valid_skill_name("2fast"), "must start with a letter");
        assert!(!valid_skill_name("_private"), "must start with a letter");
        assert!(!valid_skill_name("My-Skill"), "no uppercase / hyphens");
        assert!(!valid_skill_name("a/b"), "no path separators");
    }

    #[test]
    fn scaffold_creates_registry_shaped_skill() {
        let parent = tmpdir("create");
        let dir = scaffold_into(&parent, "demo_skill").unwrap();
        assert_eq!(dir, parent.join("demo_skill"));

        // The manifest must be what the registry scans: parseable YAML whose
        // `name` matches, with the container/permissions blocks present.
        let manifest: serde_json::Value = serde_yaml::from_str(
            &std::fs::read_to_string(dir.join("manifest.yml")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["name"].as_str(), Some("demo_skill"));
        assert_eq!(manifest["container"]["image"].as_str(), Some("noo-sandbox-base:latest"));
        assert_eq!(
            manifest["container"]["command"],
            serde_json::json!(["python", "/skill/run.py"])
        );
        // Fail-closed defaults: nothing open until the author opts in.
        assert_eq!(manifest["container"]["network"].as_str(), Some("none"));
        assert_eq!(manifest["permissions"]["shell"].as_bool(), Some(false));

        // run.py exists and speaks the SKILL_INPUT contract.
        let run_py = std::fs::read_to_string(dir.join("run.py")).unwrap();
        assert!(run_py.contains("SKILL_INPUT"));
        assert!(run_py.contains("hello_greeter"), "must point at the worked example");
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn scaffold_output_is_scannable_by_scan_skills_shape() {
        // The exact glob the registry (and skills_list) uses is
        // `*/manifest.yml` under a search dir — the scaffold's output must
        // land on it without any post-editing.
        let parent = tmpdir("scan");
        scaffold_into(&parent, "scan_me").unwrap();
        assert!(parent.join("scan_me").join("manifest.yml").is_file());
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn scaffold_refuses_existing_dir_and_bad_names() {
        let parent = tmpdir("refuse");
        scaffold_into(&parent, "dup").unwrap();
        let err = scaffold_into(&parent, "dup").unwrap_err();
        assert!(err.contains("already exists"), "{err}");

        let err = scaffold_into(&parent, "Bad-Name").unwrap_err();
        assert!(err.contains("invalid skill name"), "{err}");
        assert!(!parent.join("Bad-Name").exists(), "nothing written on a bad name");
        let _ = std::fs::remove_dir_all(&parent);
    }
}
