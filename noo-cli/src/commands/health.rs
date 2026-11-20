// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo health` — gateway liveness.

use crate::http::get_json;
use crate::output::{next_cmd, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo health` — gateway liveness. Exit 0 iff reachable AND healthy.
///
/// The gateway's `/health` (gateway-rust `routes/core.rs`) answers HTTP 200
/// with `status: "degraded"` and a per-dependency `dependencies` map when
/// Postgres/NATS/Redis are down. This used to return Ok(0) unconditionally
/// and discard `dependencies` — so `noo health` exited 0 on a gateway that
/// had lost its database, and never said which dependency was down.
pub fn health(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    // AUTHENTICATED. `/health` answers anyone, but it only itemises the
    // dependencies for a credential — the anonymous body is liveness and
    // nothing else. Without this the dependency table silently vanished
    // for a logged-in operator.
    let body = get_json(g, "/health", true, 10);
    let status = body["status"].as_str().unwrap_or("unknown");
    let healthy = matches!(status, "healthy" | "ok");
    if g.json {
        // The gateway's body as it came, plus what the text tells a person:
        // `needs_login` when the dependencies were withheld, `next` the
        // commands the text suggests.
        let mut body = body;
        with_guidance(&mut body, healthy);
        println!("{body}");
    } else {
        let host = crate::role::detect().label();
        println!("{}", ui::header("gateway", Some(&format!("host {host}"))));
        print!("{}", ui::kv(&[("status", ui::state(status))]));
        if needs_login(&body) {
            // Say why the table is missing rather than showing status alone
            // and letting the reader wonder what happened to it.
            println!(
                "{}",
                ui::muted("dependencies need a credential — run `noo auth login` to see them")
            );
        }
        if let Some(deps) = body["dependencies"].as_object() {
            println!("{}", ui::section("dependencies"));
            let rows: Vec<Vec<String>> = deps
                .iter()
                .map(|(name, d)| {
                    let (glyph, word) = match d["healthy"].as_bool() {
                        Some(true) => (Glyph::Ok, "ok"),
                        Some(false) => (Glyph::Err, "down"),
                        None => (Glyph::Warn, "not reported"),
                    };
                    let note = if d["optional"].as_bool().unwrap_or(false) { "optional" } else { "" };
                    vec![ui::glyph_cell(glyph), name.clone(), ui::state(word), note.to_string()]
                })
                .collect();
            print!("{}", ui::table(&[Col::left(""), Col::left("dependency"), Col::left("state"), Col::left("")], &rows));
        }
        if !healthy {
            let steps = unhealthy_steps(&body);
            let entries: Vec<(&str, &str)> = steps.iter().map(|(c, w)| (c.as_str(), *w)).collect();
            ui::guide(&entries);
        }
    }
    Ok(if healthy { 0 } else { ExitCode::RemoteError as i32 })
}

/// The body withholds `dependencies` from an anonymous caller: the text says
/// "run `noo auth login` to see them". Pure.
fn needs_login(body: &serde_json::Value) -> bool {
    body["dependencies"].as_object().is_none()
}

/// What `noo stack logs` takes for a `/health` dependency name. The gateway
/// names its dependencies (gateway-rust `routes/core.rs` `health`) by what
/// it checks, not by container: `postgresql` is the `postgres` container,
/// and `systems`, `addon_caller` and `fds` are checks inside the gateway
/// itself, so their cause is in the gateway's log. An unknown name passes
/// through: `noo stack logs` tries it as a container and docker says if
/// there is none.
pub(crate) fn dependency_log_target(dependency: &str) -> &str {
    match dependency {
        "postgresql" => "postgres",
        "nats" => "nats",
        "redis" => "redis",
        "systems" | "addon_caller" | "fds" => "gateway",
        other => other,
    }
}

/// What the text suggests on an unhealthy gateway, with why: the stack's
/// status, each down dependency's log, then docker repair. Pure.
fn unhealthy_steps(body: &serde_json::Value) -> Vec<(String, &'static str)> {
    let down: Vec<String> = body["dependencies"]
        .as_object()
        .map(|m| m.iter().filter(|(_, d)| d["healthy"].as_bool() == Some(false)).map(|(n, _)| n.clone()).collect())
        .unwrap_or_default();
    let mut steps = vec![("noo stack status".to_string(), "shows which container is not running")];
    // Several dependencies can share one container (the gateway's own
    // checks): name each log command once.
    for d in &down {
        let cmd = format!("noo stack logs {}", dependency_log_target(d));
        if !steps.iter().any(|(c, _)| *c == cmd) {
            steps.push((cmd, "the dependency's own log usually names the cause"));
        }
    }
    steps.push(("noo doctor docker".to_string(), "if containers look damaged after an unclean shutdown"));
    steps
}

/// Add to the gateway's body (its fields kept) what the text says:
/// `needs_login: true` when the dependencies were withheld, and `next` (the
/// login, then the unhealthy steps; `[]` on a healthy, logged-in answer).
/// Pure.
fn with_guidance(body: &mut serde_json::Value, healthy: bool) {
    if !body.is_object() {
        return;
    }
    let mut next = Vec::new();
    if needs_login(body) {
        body["needs_login"] = serde_json::json!(true);
        next.push(next_cmd("noo auth login", &[]));
    }
    if !healthy {
        next.extend(unhealthy_steps(body).iter().map(|(c, _)| next_cmd(c, &[])));
    }
    body["next"] = serde_json::Value::Array(next);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No `dependencies` in the body (anonymous): `needs_login` and the
    /// login step, the body's own fields kept.
    #[test]
    fn health_json_says_needs_login_when_dependencies_are_withheld() {
        let mut body = serde_json::json!({ "status": "healthy" });
        with_guidance(&mut body, true);
        assert_eq!(body["needs_login"], true);
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["next"], serde_json::json!([{ "kind": "command", "command": "noo auth login" }]));
        let mut body = serde_json::json!({ "status": "healthy", "dependencies": { "postgres": { "healthy": true } } });
        with_guidance(&mut body, true);
        assert!(body.get("needs_login").is_none());
        assert_eq!(body["next"], serde_json::json!([]));
    }

    /// Unhealthy: `next` is the text guide's commands, in its order.
    #[test]
    fn health_json_next_is_the_text_guide() {
        let mut body = serde_json::json!({ "status": "degraded", "dependencies": {
            "postgres": { "healthy": false }, "nats": { "healthy": true } } });
        with_guidance(&mut body, false);
        let cmds: Vec<&str> = body["next"].as_array().unwrap().iter().filter_map(|s| s["command"].as_str()).collect();
        assert_eq!(cmds, ["noo stack status", "noo stack logs postgres", "noo doctor docker"]);
        let text: Vec<String> = unhealthy_steps(&body).into_iter().map(|(c, _)| c).collect();
        assert_eq!(cmds, text);
    }

    /// Every dependency the gateway's `/health` can list maps to a
    /// container `noo stack logs` resolves (`resolve_container` adds the
    /// `noo-` prefix): postgres, nats, redis, gateway.
    #[test]
    fn health_dependency_names_map_to_stack_logs_containers() {
        let cases = [
            ("postgresql", "postgres"),
            ("nats", "nats"),
            ("redis", "redis"),
            ("systems", "gateway"),
            ("addon_caller", "gateway"),
            ("fds", "gateway"),
        ];
        for (dep, container) in cases {
            assert_eq!(dependency_log_target(dep), container, "dependency {dep}");
        }
    }
}
