// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo browser` — browser-automation session management (gateway HTTP).
//! status / open / stop, mirroring src/noomesh/browser_cli.py.

use crate::http::{get_json, post_json};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo browser status` — GET /api/tools/browser/status
pub fn browser_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/tools/browser/status", true, 5);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    // The status route reports only a COUNT (`active_sessions`); the session
    // records come from GET /sessions, whose reply is `{sessions:[..]}`.
    let list = get_json(g, "/api/tools/browser/sessions", true, 5);
    let sessions = session_list(&list);
    if sessions.is_empty() {
        println!("{}", ui::muted("no active browser sessions"));
        return Ok(0);
    }
    let map = &sessions;
    println!("{}", ui::header("browser sessions", Some(&format!("{} active", map.len()))));
    println!("{}", ui::section("sessions"));
    let rows: Vec<Vec<String>> = map
        .iter()
        .map(|info| {
            let sid = info["session_id"].as_str().unwrap_or("");
            vec![
                ui::glyph_cell(Glyph::Ok),
                ui::muted(sid),
                info["container_name"].as_str().unwrap_or("").to_string(),
                info["node_id"].as_str().unwrap_or("local").to_string(),
                idle_secs(info).map(|v| format!("{v}s")).unwrap_or_default(),
                info["base_url"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::left("session"),
                Col::left("container"),
                Col::left("node"),
                Col::right("idle"),
                Col::left("url"),
            ],
            &rows,
        )
    );
    Ok(0)
}

/// `noo browser open URL [--node N]` — POST /api/tools/browser/action (navigate)
pub fn browser_open(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut url: Option<String> = None;
    let mut node: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--node" | "-n" => node = Some(iter.next().ok_or(Unhandled)?.clone()),
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if url.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(url) = url else { return Err(Unhandled) };

    let body = serde_json::json!({
        "action": "navigate",
        "params": { "url": url, "node_id": node, "screenshot": false },
    });
    let resp = post_json(g, "/api/tools/browser/action", &body, true, 60);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    if let Some(page) = navigate_page(&resp) {
        ui::done(&format!("navigated to {}", page["url"].as_str().unwrap_or(&url)));
        // The page is the RESULT: stdout.
        print!(
            "{}",
            ui::kv(&[
                ("url", page["url"].as_str().unwrap_or(&url).to_string()),
                ("title", page["title"].as_str().unwrap_or("").to_string()),
            ])
        );
        if let Some(text) = page["text"].as_str().filter(|t| !t.is_empty()) {
            let preview: String = text.chars().take(500).collect();
            let ellipsis = if text.chars().count() > 500 { "…" } else { "" };
            println!("{}", ui::section("text"));
            println!("{preview}{ellipsis}");
        }
        ui::guide(&[
            ("noo browser status", "the session this page lives in, and any others"),
            ("noo browser stop", "closes the sessions when you are done"),
        ]);
        Ok(0)
    } else {
        ui::failed(navigate_error(&resp), Some("noo browser status"));
        Ok(1)
    }
}

/// `noo browser stop [SESSION_ID]` — stop one session, or all when omitted.
pub fn browser_stop(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let sid = match args {
        [] => None,
        [s] if !s.starts_with('-') => Some(s.clone()),
        _ => return Err(Unhandled),
    };
    let empty = serde_json::json!({});

    if let Some(sid) = sid {
        post_json(g, &format!("/api/tools/browser/sessions/{sid}/stop"), &empty, true, 10);
        if g.json {
            println!("{}", serde_json::json!({"status": "ok", "stopped": sid}));
        } else {
            ui::done(&format!("session {sid} stopped"));
            ui::guide(&[("noo browser status", "lists the sessions still open")]);
        }
        return Ok(0);
    }

    // Stop all: list then stop each.
    let list = get_json(g, "/api/tools/browser/sessions", true, 5);
    let sessions = session_list(&list);
    if sessions.is_empty() {
        if g.json {
            println!("{}", serde_json::json!({"status": "ok", "stopped": []}));
        } else {
            ui::done("no active sessions to stop");
        }
        return Ok(0);
    }
    let mut stopped = Vec::new();
    if !g.json {
        ui::step(&format!("stopping {} session(s)", sessions.len()));
    }
    for s in &sessions {
        if let Some(id) = s["session_id"].as_str() {
            post_json(g, &format!("/api/tools/browser/sessions/{id}/stop"), &empty, true, 10);
            stopped.push(id.to_string());
            if !g.json {
                println!("{}", ui::sub(&ui::status_line(Glyph::Ok, &format!("stopped {id}"))));
            }
        }
    }
    if g.json {
        println!("{}", serde_json::json!({"status": "ok", "stopped": stopped}));
    } else {
        ui::close_done(&format!("{} session(s) stopped", stopped.len()));
        ui::guide(&[("noo browser status", "confirms nothing is left open")]);
    }
    Ok(0)
}

/// The session records in a `GET /api/tools/browser/sessions` reply, which is
/// `{"sessions": [ {session_id, container_name, node_id, base_url,
/// started_at, last_action}, .. ], "engine": "rust"}`.
fn session_list(reply: &serde_json::Value) -> Vec<serde_json::Value> {
    reply["sessions"].as_array().cloned().unwrap_or_default()
}

/// Seconds since the session's last action (`last_action` is epoch seconds).
fn idle_secs(info: &serde_json::Value) -> Option<i64> {
    let last = info["last_action"].as_f64()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs_f64();
    Some((now - last).max(0.0) as i64)
}

/// A successful navigate reply is the container's raw page
/// `{url, title, text, screenshot_b64}`; a failure is `{"error": ..}`.
fn navigate_page(resp: &serde_json::Value) -> Option<&serde_json::Value> {
    if resp.get("error").is_some() || !resp.is_object() {
        return None;
    }
    resp.get("url").map(|_| resp)
}

fn navigate_error(resp: &serde_json::Value) -> &str {
    resp["error"].as_str().unwrap_or("the browser container returned no page")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Shapes copied from gateway-rust/src/routes/ui.rs (browser_sessions,
    // browser_action relaying the container's /navigate reply).
    #[test]
    fn sessions_reply_is_an_object_with_a_sessions_array() {
        let reply = json!({"sessions": [
            {"session_id": "ab12cd34", "container_name": "noo-browser-ab12cd34",
             "node_id": "local", "base_url": "http://x:9", "started_at": 1.0, "last_action": 2.0}
        ], "engine": "rust"});
        let list = session_list(&reply);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["session_id"], "ab12cd34");
        assert!(idle_secs(&list[0]).unwrap() > 0);
        assert!(session_list(&json!({"sessions": [], "engine": "rust"})).is_empty());
    }

    #[test]
    fn navigate_accepts_the_raw_container_page() {
        let resp = json!({"url": "https://example.com/", "title": "Example", "text": "hi", "screenshot_b64": null});
        assert_eq!(navigate_page(&resp).unwrap()["title"], "Example");
    }

    #[test]
    fn navigate_error_reply_is_a_failure() {
        let resp = json!({"error": "No browser session: x"});
        assert!(navigate_page(&resp).is_none());
        assert_eq!(navigate_error(&resp), "No browser session: x");
    }
}
