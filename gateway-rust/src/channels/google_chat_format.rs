// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Google Chat message shaping — event parsing, reply targeting, and
//! Markdown→Chat rendering.
//!
//! Stage 1 (retire `noomesh/channels/`). These are the pure
//! parts of the pipeline: no I/O, no state, so they port exactly and are
//! testable in isolation. Wiring (conversation resolution → inference →
//! send) lands on top of these.
//!
//! Every rule here was a real bug at some point. The comments say which,
//! because each one is easy to "simplify" back into breakage.

use serde_json::Value;

/// Where a reply goes and how it threads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyTarget {
    /// Space name for a room, user name for a DM.
    pub recipient: String,
    pub thread_id: Option<String>,
    /// `"space"` (named room) or `"private"` (DM).
    pub chat_type: String,
}

/// A parsed inbound Chat event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEvent {
    pub event_type: String,
    pub sender_id: String,
    pub sender_name: String,
    pub text: String,
    pub space_name: String,
    pub thread_id: Option<String>,
    pub chat_type: String,
}

/// Parse a Chat event envelope into the fields the pipeline needs.
///
/// Google sends `space.type == "DM"` for direct messages and `ROOM` for named
/// spaces; everything downstream keys off the normalized `chat_type`, because
/// DM and space differ in BOTH reply address and threading.
pub fn parse_event(body: &Value) -> ParsedEvent {
    // v2 (Workspace Add-on) nests the message payload under `chat`. Consulted
    // only as a fallback, so v1 events parse exactly as before — but without
    // it a v2 card click resolves to an empty space and the approval ack has
    // nowhere to go.
    let v2 = body.get("chat");
    let v2_payload = v2.and_then(|c| c.get("messagePayload"));
    // The MESSAGE is messagePayload.message, one level below the payload.
    // Reading messagePayload itself as the message (the original fallback)
    // made `message.text` resolve to a field that doesn't exist, so every
    // v2 DM parsed as empty text and hit the silent MESSAGE-gate skip —
    // pulled, acked, dispatched, answered nothing (live, 2026-08-08). The
    // Python adapter always read `msg_payload.get("message")`.
    let v2_message = v2_payload
        .and_then(|mp| mp.get("message"))
        .cloned()
        .unwrap_or(Value::Null);

    let message = body
        .get("message")
        .cloned()
        .filter(|m| !m.is_null())
        .unwrap_or(v2_message);
    let space = message
        .get("space")
        .or_else(|| body.get("space"))
        // v2 carries the space beside the message, not inside it.
        .or_else(|| v2_payload.and_then(|mp| mp.get("space")))
        .cloned()
        .unwrap_or(Value::Null);
    let sender = message
        .get("sender")
        .or_else(|| body.get("user"))
        .or_else(|| v2.and_then(|c| c.get("user")))
        .cloned()
        .unwrap_or(Value::Null);

    let space_type = space.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let chat_type = if space_type == "DM" { "private" } else { "space" };

    ParsedEvent {
        event_type: body
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("MESSAGE")
            .to_string(),
        sender_id: sender
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        sender_name: sender
            .get("displayName")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string(),
        text: message
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        space_name: space
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        thread_id: message
            .get("thread")
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
        chat_type: chat_type.to_string(),
    }
}

/// Resolve where the reply goes.
///
/// ALWAYS the space when the event names one — a DM is also a space
/// (`spaces/…`), and the send path builds
/// `https://chat.googleapis.com/v1/{recipient}/messages`, for which a
/// `users/…` recipient is a guaranteed 404 (there is no
/// `/v1/users/*/messages` in the Chat API). The old rule routed DM replies
/// to the sender id, so every DM reply 404'd after inference completed —
/// found live 2026-08-08, the last link in the channel-verification chain.
/// The sender id remains only as a last-resort fallback for an event with
/// no space name at all, where a doomed request beats an empty recipient.
pub fn resolve_reply_target(ev: &ParsedEvent) -> ReplyTarget {
    let recipient = if !ev.space_name.is_empty() {
        ev.space_name.clone()
    } else {
        ev.sender_id.clone()
    };
    ReplyTarget {
        recipient,
        thread_id: ev.thread_id.clone(),
        chat_type: ev.chat_type.clone(),
    }
}

/// `messageReplyOption` for a send, or `None` to omit the parameter.
///
/// Per the Chat API, this is "only supported in named spaces", and omitting
/// it defaults to `MESSAGE_REPLY_OPTION_UNSPECIFIED` — *"Starts a new thread.
/// Using this option ignores any thread ID or threadKey that's included."*
/// That default is exactly why a threaded space reply carrying only
/// `thread.name` landed in a NEW thread nobody saw.
///
/// So a threaded named-space reply MUST send
/// `REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD` (reply in-thread, degrade to a new
/// thread if the ref is stale). A DM must NEVER send it: it's a no-op there,
/// and sending it alongside the inbound `thread.name` is what made a DM reply
/// render detached. Both directions were real bugs — do not "simplify" this
/// to a single branch.
pub fn reply_option(chat_type: &str, threaded: bool) -> Option<&'static str> {
    if threaded && chat_type == "space" {
        Some("REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD")
    } else {
        None
    }
}

/// Convert common Markdown to Google Chat's own formatting.
///
/// Chat is NOT Markdown. It uses `*bold*` (single asterisks), `_italic_`,
/// `~strike~`, backtick code, and `<url|label>` links — and has no headers at
/// all. LLM output arrives as standard Markdown, so `**bold**` and `#` would
/// otherwise render as literal characters in the room.
///
/// Code spans are protected first so nothing inside them is rewritten.
pub fn md_to_chat(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }

    // Stash code (fenced first, then inline) behind sentinels.
    let mut protected: Vec<String> = Vec::new();
    let mut out = String::with_capacity(text.len());

    // Fenced blocks.
    let mut rest = text;
    while let Some(start) = rest.find("```") {
        let after = &rest[start + 3..];
        if let Some(end) = after.find("```") {
            out.push_str(&rest[..start]);
            protected.push(rest[start..start + 3 + end + 3].to_string());
            out.push_str(&format!("\u{0}{}\u{0}", protected.len() - 1));
            rest = &rest[start + 3 + end + 3..];
        } else {
            break;
        }
    }
    out.push_str(rest);

    // Inline code.
    let mut staged = String::with_capacity(out.len());
    let mut chars = out.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '`' {
            let mut span = String::from("`");
            let mut closed = false;
            for c2 in chars.by_ref() {
                span.push(c2);
                if c2 == '`' {
                    closed = true;
                    break;
                }
                if c2 == '\n' {
                    break;
                }
            }
            if closed {
                protected.push(span);
                staged.push_str(&format!("\u{0}{}\u{0}", protected.len() - 1));
            } else {
                staged.push_str(&span);
            }
        } else {
            staged.push(c);
        }
    }

    // Line-level: headers → bold (Chat has none), bullets → "•".
    let mut lines: Vec<String> = Vec::new();
    for line in staged.split('\n') {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        if trimmed.starts_with('#') {
            let hashes = trimmed.chars().take_while(|c| *c == '#').count();
            let body = trimmed[hashes..].trim_start();
            if hashes <= 6 && !body.is_empty() {
                lines.push(format!("*{}*", body.trim_end()));
                continue;
            }
        }
        let is_bullet = (trimmed.starts_with("- ")
            || trimmed.starts_with("* ")
            || trimmed.starts_with("+ "))
            && trimmed.len() > 2;
        if is_bullet {
            lines.push(format!("{indent}• {}", &trimmed[2..]));
        } else {
            lines.push(line.to_string());
        }
    }
    let mut result = lines.join("\n");

    result = replace_paired(&result, "**", "*");
    result = replace_paired(&result, "__", "*");
    result = replace_paired(&result, "~~", "~");
    result = md_links_to_chat(&result);

    // Restore code spans.
    for (i, span) in protected.iter().enumerate() {
        result = result.replace(&format!("\u{0}{i}\u{0}"), span);
    }
    result
}

/// Replace a paired delimiter (`**x**` → `*x*`) without a regex engine.
fn replace_paired(text: &str, from: &str, to: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(from) {
        let after = &rest[start + from.len()..];
        match after.find(from) {
            Some(end) if end > 0 => {
                out.push_str(&rest[..start]);
                out.push_str(to);
                out.push_str(&after[..end]);
                out.push_str(to);
                rest = &after[end + from.len()..];
            }
            _ => break,
        }
    }
    out.push_str(rest);
    out
}

/// `[label](https://url)` → `<https://url|label>`.
fn md_links_to_chat(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(lb) = rest.find('[') {
        let Some(rb_rel) = rest[lb..].find(']') else { break };
        let rb = lb + rb_rel;
        if rest.len() <= rb + 1 || !rest[rb + 1..].starts_with('(') {
            out.push_str(&rest[..=rb]);
            rest = &rest[rb + 1..];
            continue;
        }
        let Some(rp_rel) = rest[rb + 2..].find(')') else { break };
        let rp = rb + 2 + rp_rel;
        let label = &rest[lb + 1..rb];
        let url = &rest[rb + 2..rp];
        if url.starts_with("http://") || url.starts_with("https://") {
            out.push_str(&rest[..lb]);
            out.push_str(&format!("<{url}|{label}>"));
        } else {
            out.push_str(&rest[..=rp]);
        }
        rest = &rest[rp + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn space_event() -> Value {
        json!({
            "type": "MESSAGE",
            "message": {
                "text": "hello",
                "thread": {"name": "spaces/S/threads/T"},
                "sender": {"name": "users/1", "displayName": "Alice"},
                "space": {"name": "spaces/S", "type": "ROOM"}
            }
        })
    }

    fn dm_event() -> Value {
        json!({
            "type": "MESSAGE",
            "message": {
                "text": "hi",
                "thread": {"name": "spaces/D/threads/T"},
                "sender": {"name": "users/2", "displayName": "Bob"},
                "space": {"name": "spaces/D", "type": "DM"}
            }
        })
    }

    #[test]
    fn parses_space_and_dm_types() {
        assert_eq!(parse_event(&space_event()).chat_type, "space");
        assert_eq!(parse_event(&dm_event()).chat_type, "private");
    }

    #[test]
    fn space_replies_to_the_space_not_the_sender() {
        // Addressing sender_id would open a DM instead of answering the room.
        let t = resolve_reply_target(&parse_event(&space_event()));
        assert_eq!(t.recipient, "spaces/S");
    }

    #[test]
    fn dm_replies_to_the_dm_space_not_the_user_id() {
        // A DM is a space too (spaces/…). The send URL is
        // /v1/{recipient}/messages, and /v1/users/*/messages does not exist
        // — routing DM replies at the sender id 404'd every DM reply
        // (live, 2026-08-08).
        let t = resolve_reply_target(&parse_event(&dm_event()));
        assert!(
            t.recipient.starts_with("spaces/"),
            "DM reply must target the DM space, got {}",
            t.recipient
        );
    }

    #[test]
    fn missing_space_name_falls_back_to_sender() {
        let mut ev = parse_event(&space_event());
        ev.space_name = String::new();
        assert_eq!(resolve_reply_target(&ev).recipient, "users/1");
        let mut dm = parse_event(&dm_event());
        dm.space_name = String::new();
        assert_eq!(resolve_reply_target(&dm).recipient, "users/2");
    }

    #[test]
    fn reply_option_only_for_threaded_spaces() {
        // Both directions were real bugs: a space without the option starts a
        // NEW thread; a DM with it renders detached.
        assert_eq!(
            reply_option("space", true),
            Some("REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD")
        );
        assert_eq!(reply_option("private", true), None);
        assert_eq!(reply_option("space", false), None);
    }

    #[test]
    fn bold_and_headers_become_chat_formatting() {
        assert_eq!(md_to_chat("**bold**"), "*bold*");
        assert_eq!(md_to_chat("## Title"), "*Title*");
        assert_eq!(md_to_chat("__also bold__"), "*also bold*");
        assert_eq!(md_to_chat("~~gone~~"), "~gone~");
    }

    #[test]
    fn bullets_become_dots() {
        assert_eq!(md_to_chat("- one\n- two"), "• one\n• two");
        assert_eq!(md_to_chat("  * nested"), "  • nested");
    }

    #[test]
    fn links_become_chat_syntax() {
        assert_eq!(
            md_to_chat("see [docs](https://example.com)"),
            "see <https://example.com|docs>"
        );
        // Non-http targets are left alone rather than mangled.
        assert_eq!(md_to_chat("[x](mailto:a@b.c)"), "[x](mailto:a@b.c)");
    }

    #[test]
    fn code_spans_are_not_rewritten() {
        assert_eq!(md_to_chat("`**not bold**`"), "`**not bold**`");
        assert_eq!(
            md_to_chat("```\n## not a header\n```"),
            "```\n## not a header\n```"
        );
    }

    #[test]
    fn plain_text_is_untouched() {
        assert_eq!(md_to_chat("just words"), "just words");
        assert_eq!(md_to_chat(""), "");
    }

    /// The live 2026-08-08 regression: a v2 (Workspace Add-on) DM. The
    /// message lives at chat.messagePayload.MESSAGE — reading
    /// messagePayload itself as the message made text parse empty and the
    /// pipeline silently skip every v2 DM (pulled, acked, no reply).
    /// Shape mirrors the Python adapter's documented v2 example.
    #[test]
    fn v2_dm_message_parses_text_space_and_sender() {
        let ev = json!({
            "chat": {
                "user": {"name": "users/1152", "displayName": "Alice"},
                "eventTime": "2026-08-08T16:09:39Z",
                "messagePayload": {
                    "message": {
                        "name": "spaces/AAA/messages/BBB",
                        "text": "hello mesh",
                        "thread": {"name": "spaces/AAA/threads/TTT"}
                    },
                    "space": {"name": "spaces/AAA", "type": "DM"}
                }
            }
        });
        let p = parse_event(&ev);
        assert_eq!(p.event_type, "MESSAGE");
        assert_eq!(p.text, "hello mesh");
        assert_eq!(p.space_name, "spaces/AAA");
        assert_eq!(p.chat_type, "private");
        assert_eq!(p.sender_id, "users/1152");
        assert_eq!(p.sender_name, "Alice");
        assert_eq!(p.thread_id.as_deref(), Some("spaces/AAA/threads/TTT"));
    }

    /// v1 events must parse exactly as before the v2 fix (the fallback is
    /// only consulted when body.message is absent).
    #[test]
    fn v1_message_parse_unchanged_by_v2_fix() {
        let ev = json!({
            "type": "MESSAGE",
            "message": {"text": "hi", "thread": {"name": "spaces/S/threads/T"}},
            "user": {"name": "users/9", "displayName": "U"},
            "space": {"name": "spaces/S", "type": "ROOM"}
        });
        let p = parse_event(&ev);
        assert_eq!(p.text, "hi");
        assert_eq!(p.space_name, "spaces/S");
        assert_eq!(p.chat_type, "space");
        assert_eq!(p.sender_id, "users/9");
    }
}
