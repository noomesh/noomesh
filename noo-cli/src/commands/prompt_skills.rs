// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo prompt-skills …` — prompt skill templates (Rust gateway routes in
//! `routes/settings.rs`).
//!
//! Ported: list, info (alias `get`), create, evolve.
//! Left in Python: nothing — the whole group is ported.

use super::truncate;
use crate::http::{get_json, post_json};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col};
use crate::{Globals, Unhandled};

/// `noo prompt-skills list` — GET /api/prompt-skills.
pub fn prompt_skills_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/prompt-skills", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let skills = body["skills"].as_array().or_else(|| body.as_array()).unwrap_or(&empty);
    if skills.is_empty() {
        println!("{}", ui::muted("no prompt skills"));
        return Ok(0);
    }
    println!("{}", ui::header("prompt skills", Some(&format!("{} skills", skills.len()))));
    println!();
    let rows: Vec<Vec<String>> = skills
        .iter()
        .map(|s| {
            vec![
                truncate(s["name"].as_str().unwrap_or("?"), 28),
                s["priority"].as_u64().unwrap_or(5).to_string(),
                format!("{:.1}", s["fitness"].as_f64().unwrap_or(0.0)),
                if s["is_core"].as_bool().unwrap_or(false) { "yes".into() } else { String::new() },
                // An older gateway sends no trust: shown blank, not guessed.
                s["trust"].as_str().unwrap_or("").to_string(),
                ui::muted(&truncate(s["description"].as_str().unwrap_or(""), 60)),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left("name"), Col::right("priority"), Col::right("fitness"), Col::left("core"), Col::left("trust"), Col::left("description")],
            &rows,
        )
    );
    Ok(0)
}

/// The reason the gateway refused a skill request, if it did. The skill
/// routes answer failures as HTTP 200 with a top-level `error`.
fn skill_error(body: &serde_json::Value) -> Option<&str> {
    body["error"].as_str().map(str::trim).filter(|e| !e.is_empty())
}

/// What the gateway's `POST /api/prompt-skills` answered: `Ok(())` for
/// `{"status":"created","name":...,"path":...}`, else the reason it gave
/// (`{"error": ...}`) or the raw body. There is no `ok` key in the reply.
fn create_outcome(resp: &serde_json::Value) -> Result<(), String> {
    if resp["status"].as_str() == Some("created") && skill_error(resp).is_none() {
        return Ok(());
    }
    Err(skill_error(resp)
        .map(str::to_string)
        .or_else(|| resp["detail"].as_str().map(str::to_string))
        .unwrap_or_else(|| resp.to_string()))
}

/// `noo prompt-skills info NAME` (hidden alias `get`) — GET /api/prompt-skills/{name}.
pub fn prompt_skills_info(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [name] = args else { return Err(Unhandled) };
    if name.starts_with('-') {
        return Err(Unhandled);
    }
    let body = get_json(g, &format!("/api/prompt-skills/{}", super::urlencode(name)), true, 10);
    if g.json {
        println!("{body}");
        return Ok(super::json_exit(&body));
    }
    // An unknown name is HTTP 200 `{"error": "... not found"}`, not a 404.
    if let Some(why) = skill_error(&body) {
        fail(
            false,
            ExitCode::RemoteError,
            "skill_not_found",
            why,
            Some("`noo prompt-skills list` shows the skills that exist"),
        );
    }
    let desc = body["description"].as_str().unwrap_or("");
    println!("{}", ui::header(body["name"].as_str().unwrap_or(name), if desc.is_empty() { None } else { Some(desc) }));
    let tags = body["tags"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
        .unwrap_or_default();
    print!(
        "{}",
        ui::kv(&[
            ("tags", if tags.is_empty() { ui::dash().to_string() } else { tags }),
            ("priority", body["priority"].as_u64().unwrap_or(5).to_string()),
            ("fitness", format!("{:.1}", body["fitness"].as_f64().unwrap_or(0.0))),
            ("author", body["author"].as_str().unwrap_or(ui::dash()).to_string()),
        ])
    );
    // The skill body is data: printed verbatim after a section label.
    if let Some(content) = body["content"].as_str() {
        if !content.is_empty() {
            println!("{}", ui::section("content"));
            println!("{content}");
        }
    }
    Ok(0)
}

/// `noo prompt-skills create NAME [--file/-f PATH] [--description/-d TEXT]
/// [--tags CSV] [--priority/-p N]` — POST /api/prompt-skills.
/// Content comes from `--file`, otherwise stdin is read to EOF (Python
/// parity; the "Ctrl-D to finish" hint goes to stderr, TTY-only).
pub fn prompt_skills_create(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut name: Option<String> = None;
    let mut file: Option<String> = None;
    let mut description: Option<String> = None;
    let mut tags: Option<String> = None;
    let mut priority: u64 = 5;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--file" | "-f" => file = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--description" | "-d" => description = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--tags" => tags = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--priority" | "-p" => {
                priority = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if name.replace(t.to_string()).is_some() {
                    return Err(Unhandled); // two positionals — not our surface
                }
            }
        }
    }
    let Some(name) = name else { return Err(Unhandled) };

    let content = match &file {
        Some(f) => match std::fs::read_to_string(f) {
            Ok(c) => c,
            Err(_) => fail(
                g.json,
                ExitCode::Generic,
                "file_not_found",
                &format!("file not found: {f}"),
                None,
            ),
        },
        None => {
            use std::io::Read as _;
            if !g.json && unsafe { libc::isatty(0) } == 1 {
                eprintln!("{}", ui::muted("enter skill content (Ctrl-D to finish)"));
            }
            let mut buf = String::new();
            if std::io::stdin().read_to_string(&mut buf).is_err() {
                fail(
                    g.json,
                    ExitCode::Generic,
                    "stdin_read_failed",
                    "could not read skill content from stdin",
                    Some("pass --file/-f, or pipe the markdown content in"),
                );
            }
            buf
        }
    };

    let mut body = serde_json::json!({ "name": name, "content": content, "priority": priority });
    if let Some(d) = description {
        body["description"] = d.into();
    }
    if let Some(t) = tags {
        let list: Vec<String> = t.split(',').map(|x| x.trim().to_string()).collect();
        body["tags"] = list.into();
    }
    let resp = post_json(g, "/api/prompt-skills", &body, true, 10);
    if g.json {
        println!("{resp}");
        return Ok(if create_outcome(&resp).is_ok() { 0 } else { super::json_exit(&resp).max(1) });
    }
    if create_outcome(&resp).is_ok() {
        ui::done(&format!("created skill {name}"));
        let info = format!("noo prompt-skills info {name}");
        ui::guide(&[
            (info.as_str(), "shows the stored skill and its priority"),
            ("noo prompt-skills list", "confirms it is registered"),
        ]);
        Ok(0)
    } else {
        // 2xx without status "created" — surface the gateway's reason, exit 1.
        let detail = create_outcome(&resp).unwrap_err();
        ui::failed(&detail, None);
        Ok(1)
    }
}

/// Parse `noo prompt-skills evolve` flags into the request body:
/// `--observation/-o TEXT`, `--skill NAME`, `--role ROLE`, `--apply`.
fn evolve_body(args: &[String]) -> Result<serde_json::Value, Unhandled> {
    let mut body = serde_json::json!({});
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--observation" | "-o" => {
                body["observation"] = iter.next().ok_or(Unhandled)?.as_str().into()
            }
            "--skill" => body["skill"] = iter.next().ok_or(Unhandled)?.as_str().into(),
            "--role" => body["role"] = iter.next().ok_or(Unhandled)?.as_str().into(),
            "--apply" => body["apply"] = true.into(),
            _ => return Err(Unhandled),
        }
    }
    Ok(body)
}

/// The reason evolve refused the request, if it did: a non-empty `error` on
/// the result, whatever its `action` says.
fn evolve_refusal(result: &serde_json::Value) -> Option<&str> {
    result["error"].as_str().map(str::trim).filter(|e| !e.is_empty())
}

/// `noo prompt-skills evolve [--observation/-o TEXT] [--skill NAME]
/// [--role ROLE] [--apply]` — POST /api/prompt-skills/evolve, which the
/// gateway proxies to the evolve add-on (503 with its refusal when the
/// add-on is off). Without `--apply` the answer is a proposal and nothing is
/// written; with it the add-on creates or rewrites the skill.
pub fn prompt_skills_evolve(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let body = evolve_body(args)?;
    // The add-on's LLM pass can take minutes (the gateway allows 300 s).
    let resp = post_json(g, "/api/prompt-skills/evolve", &body, true, 300);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    // Python parity: unwrap {"result": {...}} when present, else use the body.
    let result = if resp["result"].is_object() { resp["result"].clone() } else { resp };
    // The add-on answers a refusal (core skill, unknown skill, unparsable LLM
    // reply, ...) as action "none" plus an `error`. That is not "nothing to
    // do": show the reason and fail, or a refused request reads as a verdict.
    if let Some(why) = evolve_refusal(&result) {
        eprintln!("{}", ui::err(&format!("skill evolution refused: {why}")));
        return Ok(1);
    }
    let action = result["action"].as_str().unwrap_or("unknown");
    let line = |label: &str, v: &serde_json::Value| {
        if let Some(t) = v.as_str().filter(|t| !t.is_empty()) {
            println!("  {label}: {t}");
        }
    };
    if action == "none" {
        println!("{}", ui::muted("no skill evolution needed"));
        line("rationale", &result["rationale"]);
        return Ok(0);
    }
    println!("{}", ui::header("skill evolution", Some(action)));
    line("skill", &result["name"]);
    line("from", &result["target_skill"]);
    line("rationale", &result["rationale"]);
    let m = &result["moderation"];
    if m.is_object() {
        if m["passed"].as_bool() == Some(true) {
            println!("  moderation: passed");
        } else {
            let layer = m["layer"].as_str().unwrap_or("unknown layer");
            println!("  moderation: BLOCKED ({layer})");
            if let Some(issues) = m["issues"].as_array() {
                for i in issues.iter().filter_map(|i| i.as_str()) {
                    println!("    - {i}");
                }
            }
        }
    }
    if result["applied"].as_bool() == Some(true) {
        println!("  applied: generation {}", result["generation"]);
    } else if m["passed"].as_bool() == Some(true) {
        println!("{}", ui::muted("proposal only; nothing written (re-run with --apply)"));
    }
    Ok(0)
}

/// `noo prompt-skills proposals [--status <s>] [--limit <n>]` — GET
/// /api/prompt-skills/proposals. Skills written at runtime are data to the
/// model until a person promotes the text they reviewed.
pub fn prompt_skills_proposals(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut status: Option<String> = None;
    let mut limit: Option<u32> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--status" => status = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--limit" => limit = Some(iter.next().ok_or(Unhandled)?.parse().map_err(|_| Unhandled)?),
            _ => return Err(Unhandled),
        }
    }
    let mut path = String::from("/api/prompt-skills/proposals");
    let mut q: Vec<String> = Vec::new();
    if let Some(s) = &status {
        q.push(format!("status={}", super::urlencode(s)));
    }
    if let Some(l) = limit {
        q.push(format!("limit={l}"));
    }
    if !q.is_empty() {
        path = format!("{path}?{}", q.join("&"));
    }
    let body = get_json(g, &path, true, 20);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let rows = body["proposals"].as_array().unwrap_or(&empty);
    if rows.is_empty() {
        println!("{}", ui::muted("no proposals: a skill written at runtime files one"));
        return Ok(0);
    }
    println!("{}", ui::header("prompt skill proposals", Some(&format!("{} pending", body["pending"].as_u64().unwrap_or(0)))));
    println!();
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|p| {
            vec![
                p["id"].to_string(),
                ui::state(p["status"].as_str().unwrap_or("?")),
                truncate(p["name"].as_str().unwrap_or("?"), 28),
                truncate(p["proposed_by"].as_str().unwrap_or(""), 16),
                truncate(p["decided_by"].as_str().unwrap_or(""), 16),
                ui::muted(&truncate(p["description"].as_str().unwrap_or(""), 50)),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::right("id"), Col::left("status"), Col::left("skill"), Col::left("proposed by"), Col::left("decided by"), Col::left("description")],
            &table,
        )
    );
    if body["pending"].as_u64().unwrap_or(0) > 0 {
        ui::guide(&[
            ("noo prompt-skills info <skill>", "shows the text you would promote"),
            ("noo prompt-skills decide <id> --promote | --reject", "promote makes it instructions (system message); reject stops it being injected"),
        ]);
    }
    Ok(0)
}

/// `noo prompt-skills decide <id> (--promote | --reject) [--reason <text>]` —
/// POST /api/prompt-skills/proposals/{id}/decide. A person's act: the gateway
/// refuses agent, harness, MCP-door and service credentials.
pub fn prompt_skills_decide(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut id: Option<i64> = None;
    let (mut promote, mut reject) = (false, false);
    let mut reason: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--promote" => promote = true,
            "--reject" => reject = true,
            "--reason" => reason = Some(iter.next().ok_or(Unhandled)?.clone()),
            s if !s.starts_with('-') && id.is_none() => id = Some(s.parse().map_err(|_| Unhandled)?),
            _ => return Err(Unhandled),
        }
    }
    let id = id.ok_or(Unhandled)?;
    if promote == reject {
        fail(g.json, ExitCode::Usage, "usage", "Pass exactly one of --promote / --reject", Some("noo prompt-skills proposals"));
    }
    let decision = if promote { "promote" } else { "reject" };
    let body = post_json(
        g,
        &format!("/api/prompt-skills/proposals/{id}/decide"),
        &serde_json::json!({"decision": decision, "reason": reason}),
        true,
        20,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let name = body["name"].as_str().unwrap_or("?");
    if promote {
        ui::done(&format!("promoted '{name}': its reviewed text is now instructions (system message)"));
    } else {
        ui::done(&format!("rejected '{name}': it is no longer injected"));
    }
    if let Some(note) = body["live"].as_str() {
        println!("  {}", ui::muted(note));
    }
    Ok(0)
}

#[cfg(test)]
mod evolve_flag_tests {
    use super::{create_outcome, evolve_body, evolve_refusal, skill_error};

    #[test]
    fn a_refusal_is_not_a_none_verdict() {
        let refused = serde_json::json!({"action": "none", "error": "core skills are never mutated: 'cli-guide'"});
        assert_eq!(evolve_refusal(&refused), Some("core skills are never mutated: 'cli-guide'"));
        let verdict = serde_json::json!({"action": "none", "rationale": "fine"});
        assert_eq!(evolve_refusal(&verdict), None);
        assert_eq!(evolve_refusal(&serde_json::json!({"action": "none", "error": "  "})), None);
        assert_eq!(evolve_refusal(&serde_json::json!({"action": "create", "error": null})), None);
    }

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // Reply shapes copied from gateway-rust/src/routes/settings.rs
    // (`prompt_skills_create` / `prompt_skills_get`), never invented.
    #[test]
    fn create_accepts_the_gateways_created_reply() {
        let real = serde_json::json!({"status": "created", "name": "my-skill", "path": "/skills/evolved/my-skill.md"});
        assert!(create_outcome(&real).is_ok(), "the real success reply has no `ok` key");
    }

    #[test]
    fn create_reports_the_gateways_error_reply() {
        let real = serde_json::json!({"error": "Failed to write skill file: denied"});
        assert_eq!(create_outcome(&real).unwrap_err(), "Failed to write skill file: denied");
        // The old mocked shape is not a success either.
        assert!(create_outcome(&serde_json::json!({"ok": true})).is_err());
    }

    #[test]
    fn info_sees_the_not_found_reply() {
        let real = serde_json::json!({"error": "Prompt skill 'nope' not found"});
        assert_eq!(skill_error(&real), Some("Prompt skill 'nope' not found"));
        let found = serde_json::json!({"name": "x", "priority": 5, "fitness": 0.0, "content": "c"});
        assert_eq!(skill_error(&found), None);
    }

    #[test]
    fn evolve_flags_build_the_request_body() {
        let b = evolve_body(&a(&["-o", "slow loops", "--skill", "rag-tips", "--role", "coder", "--apply"])).unwrap();
        assert_eq!(
            b,
            serde_json::json!({"observation": "slow loops", "skill": "rag-tips", "role": "coder", "apply": true})
        );
        assert_eq!(evolve_body(&a(&[])).unwrap(), serde_json::json!({}), "no flag, no apply: a proposal");
    }

    #[test]
    fn evolve_rejects_unknown_flags_and_missing_values() {
        assert!(evolve_body(&a(&["--force"])).is_err());
        assert!(evolve_body(&a(&["--skill"])).is_err());
        assert!(evolve_body(&a(&["--observation"])).is_err());
    }
}
