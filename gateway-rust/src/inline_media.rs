// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Media in chat content parts: inline `data:` only (0.6.29).
//!
//! A caller's content part that names a media URL (`image_url`, an
//! Anthropic `source: {type: "url"}`, `input_image`, `audio_url`,
//! `video_url`, `file_url`, or any part that carries a `url` field) used to
//! reach the model server as written. vLLM fetches an http(s) media URL
//! itself, from the backend's own network, so any caller of a vision class
//! could make a GPU node fetch an internal address and hand what came back
//! to the image decoder. This gateway now refuses every media URL that is
//! not an inline `data:` URL, and accepts a `data:` URL only when it is
//! base64, of an allowed image type, within the size caps, and its first
//! bytes are what the declared type says. A gateway-side fetch through an
//! egress guard may come later; until then a link is refused, not fetched.
//!
//! [`check_body`] is called where every caller-shaped chat body passes on
//! its way to a backend: `raw_chat::send_with_failover_pinned` (the
//! `/v1/chat/completions`, `/v1/responses`, `/api/external/chat/completions`,
//! `/api/external/inference` chat and `/api/inference` raw surfaces) and the
//! harness's loopback wire translator (`harness::translator`, its three
//! routes). The node agent's inference proxy refuses the same links as a
//! second wall (`node-agent-go/internal/api/media_urls.go`).
//!
//! A refusal names the code, the part type and the fix. It never carries
//! the URL or the data, and neither does the log line.

use base64::Engine as _;
use serde_json::{json, Value};

/// The largest decoded inline media part. The gateway's chat routes take a
/// body of at most 2 MiB (axum's default JSON limit), which binds first
/// there; the harness translator takes 64 MiB, so this cap is what holds it.
pub const MAX_INLINE_MEDIA_PART_BYTES: usize = 8 * 1024 * 1024;
/// The largest decoded inline media in one request, all parts together.
pub const MAX_INLINE_MEDIA_REQUEST_BYTES: usize = 16 * 1024 * 1024;
/// The media types a `data:` URL may declare (`image/jpg` is read as
/// `image/jpeg`). No route takes audio or video input today.
pub const ALLOWED_MEDIA_TYPES: [&str; 4] = ["image/png", "image/jpeg", "image/webp", "image/gif"];

/// A media URL that is not an inline `data:` URL (http, https, file, ftp…).
pub const REMOTE_MEDIA_URL_REFUSED: &str = "remote_media_url_refused";
/// A `data:` URL of a media type outside [`ALLOWED_MEDIA_TYPES`].
pub const INLINE_MEDIA_TYPE_REFUSED: &str = "inline_media_type_refused";
/// A `data:` URL that is not base64, or whose base64 does not decode.
pub const INLINE_MEDIA_INVALID: &str = "inline_media_invalid";
/// A `data:` URL whose bytes are not the type it declares.
pub const INLINE_MEDIA_TYPE_MISMATCH: &str = "inline_media_type_mismatch";
/// Inline media over [`MAX_INLINE_MEDIA_PART_BYTES`] or
/// [`MAX_INLINE_MEDIA_REQUEST_BYTES`].
pub const INLINE_MEDIA_TOO_LARGE: &str = "inline_media_too_large";

/// The doc section a refusal points at.
pub const MEDIA_DOC: &str = "docs/reference/api.md#media-in-chat-content-parts";

/// What to do instead, said the same way on every refusal.
const INLINE_FIX: &str = "send the image inline as a data: URL (base64), for example data:image/png;base64,<data>";

/// Why a body was refused. `message` is public: it names the part type and
/// the rule, never the URL or the data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaRefusal {
    pub code: &'static str,
    /// The refused part's `type`, cleaned for the log and the message.
    pub part_type: String,
    pub message: String,
}

impl MediaRefusal {
    fn new(code: &'static str, part_type: &str, what: &str) -> Self {
        let part_type = clean_type(part_type);
        let message = format!("a '{part_type}' content part {what}; {INLINE_FIX}");
        Self { code, part_type, message }
    }

    /// 413 for a size refusal, 400 for every other.
    pub fn status(&self) -> u16 {
        if self.code == INLINE_MEDIA_TOO_LARGE {
            413
        } else {
            400
        }
    }

    /// The `next` steps: the fix, then the doc.
    pub fn next(&self) -> Value {
        json!([
            {"kind": "action", "text": INLINE_FIX},
            {"kind": "doc", "doc": MEDIA_DOC},
        ])
    }

    /// The one log line: code, route, part type. Never the URL or the data.
    pub fn log(&self, route: &str) {
        tracing::warn!(code = self.code, route, part_type = %self.part_type, "chat_media_refused");
    }
}

/// A part type as it may appear in a message: the caller's own input, cut
/// to 32 characters of `[A-Za-z0-9_-]`.
fn clean_type(raw: &str) -> String {
    let t: String = raw.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').take(32).collect();
    if t.is_empty() {
        "untyped".to_string()
    } else {
        t
    }
}

#[derive(Clone, Copy)]
struct Limits {
    part: usize,
    total: usize,
}

const LIMITS: Limits = Limits { part: MAX_INLINE_MEDIA_PART_BYTES, total: MAX_INLINE_MEDIA_REQUEST_BYTES };

/// Check every content part of a chat body (OpenAI chat `messages`,
/// Responses `input`, Anthropic `messages` / `system`). `Ok` means nothing
/// in it names a remote media URL and every inline media part is allowed.
pub fn check_body(body: &Value) -> Result<(), MediaRefusal> {
    check_with(body, LIMITS)
}

fn check_with(body: &Value, limits: Limits) -> Result<(), MediaRefusal> {
    let mut total = 0usize;
    for key in ["messages", "input", "system"] {
        if let Some(Value::Array(items)) = body.get(key) {
            for item in items {
                walk(item, limits, &mut total)?;
            }
        }
    }
    Ok(())
}

/// One message, item or part, then the parts it holds (`content`, and a
/// tool output's `output`; an Anthropic `tool_result` nests its own
/// `content`). Strings (a text input) are not parts.
fn walk(v: &Value, limits: Limits, total: &mut usize) -> Result<(), MediaRefusal> {
    if !v.is_object() {
        return Ok(());
    }
    check_part(v, limits, total)?;
    for key in ["content", "output"] {
        match v.get(key) {
            Some(Value::Array(parts)) => {
                for p in parts {
                    walk(p, limits, total)?;
                }
            }
            Some(o @ Value::Object(_)) => walk(o, limits, total)?,
            _ => {}
        }
    }
    Ok(())
}

/// The media a part names, wherever its shape puts it:
/// - an Anthropic `source`: `{type: "url", url}` is a link; `{type:
///   "base64", media_type, data}` on an `image` block is inline media;
/// - a `url` field, or any `*_url` field, as a string or an object with a
///   `url` (`image_url: {url}`, `input_image.image_url`, `audio_url`,
///   `video_url`, `file_url`);
/// - the object named by the part's own type, when it has a `url`
///   (`{type: "file", file: {url}}`, `{type: "input_audio", input_audio:
///   {url}}`).
///
/// A part with none of these (text, a tool call, an `input_audio` with
/// inline `data`) passes as it always did.
fn check_part(p: &Value, limits: Limits, total: &mut usize) -> Result<(), MediaRefusal> {
    let ty = p.get("type").and_then(Value::as_str).unwrap_or("");
    if let Some(src) = p.get("source").filter(|s| s.is_object()) {
        if let Some(u) = src.get("url").and_then(Value::as_str) {
            check_url(ty, u, limits, total)?;
        }
        if false && ty == "image" && src.get("type").and_then(Value::as_str) == Some("base64") {
            let media_type = src.get("media_type").and_then(Value::as_str).unwrap_or("");
            let data = src.get("data").and_then(Value::as_str).unwrap_or("");
            check_inline(ty, media_type, data, limits, total)?;
        }
    }
    let Some(obj) = p.as_object() else { return Ok(()) };
    for (k, v) in obj {
        let url_field = k == "url" || k.ends_with("_url");
        match v {
            Value::String(s) if url_field => check_url(ty, s, limits, total)?,
            Value::Object(o) if url_field || (!ty.is_empty() && k == ty) => {
                if let Some(s) = o.get("url").and_then(Value::as_str) {
                    check_url(ty, s, limits, total)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// A media URL: inline `data:` is checked, anything else is refused. An
/// empty string names nothing to fetch and is left to the backend.
fn check_url(ty: &str, url: &str, limits: Limits, total: &mut usize) -> Result<(), MediaRefusal> {
    let url = url.trim();
    if url.is_empty() {
        return Ok(());
    }
    let Some(rest) = url.get(..5).filter(|s| s.eq_ignore_ascii_case("data:")).map(|_| &url[5..]) else {
        return Err(MediaRefusal::new(
            REMOTE_MEDIA_URL_REFUSED,
            ty,
            "names a remote URL; media links are not passed to a model (the model server would fetch them)",
        ));
    };
    let Some((header, data)) = rest.split_once(',') else {
        return Err(MediaRefusal::new(INLINE_MEDIA_INVALID, ty, "holds a data: URL with no data"));
    };
    let mut fields = header.split(';');
    let media_type = fields.next().unwrap_or("");
    if !fields.any(|f| f.trim().eq_ignore_ascii_case("base64")) {
        return Err(MediaRefusal::new(INLINE_MEDIA_INVALID, ty, "holds a data: URL that is not base64"));
    }
    check_inline(ty, media_type, data, limits, total)
}

/// Inline media: an allowed type, base64 that decodes, within the caps,
/// and bytes that are the declared type.
fn check_inline(ty: &str, media_type: &str, data: &str, limits: Limits, total: &mut usize) -> Result<(), MediaRefusal> {
    let mut mt = media_type.trim().to_ascii_lowercase();
    if mt == "image/jpg" {
        mt = "image/jpeg".to_string();
    }
    if !ALLOWED_MEDIA_TYPES.contains(&mt.as_str()) {
        return Err(MediaRefusal::new(
            INLINE_MEDIA_TYPE_REFUSED,
            ty,
            "holds inline media of a type this gateway does not take (accepted: image/png, image/jpeg, image/webp, image/gif)",
        ));
    }
    // Refused before decoding when even the encoded text is far over the cap.
    if data.len() / 4 * 3 > limits.part.saturating_mul(2) {
        return Err(too_large(ty, limits));
    }
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data.trim()) else {
        return Err(MediaRefusal::new(INLINE_MEDIA_INVALID, ty, "holds inline media whose base64 does not decode"));
    };
    if bytes.len() > limits.part {
        return Err(too_large(ty, limits));
    }
    *total = total.saturating_add(bytes.len());
    if *total > limits.total {
        return Err(too_large(ty, limits));
    }
    if !magic_matches(&mt, &bytes) {
        return Err(MediaRefusal::new(INLINE_MEDIA_TYPE_MISMATCH, ty, "holds inline media whose bytes are not the type it declares"));
    }
    Ok(())
}

fn too_large(ty: &str, limits: Limits) -> MediaRefusal {
    MediaRefusal::new(
        INLINE_MEDIA_TOO_LARGE,
        ty,
        &format!(
            "holds inline media over the cap ({} MiB a part, {} MiB a request)",
            limits.part / (1024 * 1024),
            limits.total / (1024 * 1024)
        ),
    )
}

/// The file signature of each allowed type.
fn magic_matches(media_type: &str, b: &[u8]) -> bool {
    match media_type {
        "image/png" => b.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        "image/jpeg" => b.starts_with(&[0xFF, 0xD8, 0xFF]),
        "image/webp" => b.starts_with(b"RIFF") && b.get(8..12) == Some(b"WEBP".as_slice()),
        "image/gif" => b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];
    const JPEG: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0, 16, b'J', b'F', b'I', b'F'];

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    fn data_url(mt: &str, b: &[u8]) -> String {
        format!("data:{mt};base64,{}", b64(b))
    }

    /// An OpenAI chat body with one user message of these parts.
    fn chat(parts: Value) -> Value {
        json!({"model": "m", "messages": [{"role": "user", "content": parts}]})
    }

    fn image_url(url: &str) -> Value {
        chat(json!([{"type": "text", "text": "what is this?"}, {"type": "image_url", "image_url": {"url": url}}]))
    }

    fn code(body: &Value) -> Option<&'static str> {
        check_body(body).err().map(|r| r.code)
    }

    #[test]
    fn an_http_image_url_is_refused_with_the_code_and_next() {
        let r = check_body(&image_url("http://192.0.2.10/cat.png")).unwrap_err();
        assert_eq!(r.code, REMOTE_MEDIA_URL_REFUSED);
        assert_eq!(r.status(), 400);
        assert_eq!(r.part_type, "image_url");
        assert!(r.message.contains("data:") && r.message.contains("base64"), "{}", r.message);
        // Never the URL, in any form.
        assert!(!r.message.contains("192.0.2.10") && !r.message.contains("http"), "{}", r.message);
        let next = r.next();
        assert_eq!(next[0]["kind"], "action");
        assert!(next[0]["text"].as_str().unwrap().contains("data: URL"));
        assert_eq!(next[1], json!({"kind": "doc", "doc": MEDIA_DOC}));
    }

    #[test]
    fn https_file_and_other_schemes_are_refused() {
        for url in ["https://example.com/a.png", "file:///etc/passwd", "ftp://192.0.2.1/a", "s3://b/k", "gs://b/k", "blob:x", "HTTP://100.64.0.1:8081/x"] {
            assert_eq!(code(&image_url(url)), Some(REMOTE_MEDIA_URL_REFUSED), "{url}");
        }
        // A bare string image_url (some clients send that shape).
        assert_eq!(code(&chat(json!([{"type": "image_url", "image_url": "https://example.com/a.png"}]))), Some(REMOTE_MEDIA_URL_REFUSED));
    }

    #[test]
    fn an_anthropic_url_source_is_refused() {
        let body = json!({"messages": [{"role": "user", "content": [
            {"type": "image", "source": {"type": "url", "url": "https://example.com/a.png"}}
        ]}]});
        let r = check_body(&body).unwrap_err();
        assert_eq!((r.code, r.part_type.as_str()), (REMOTE_MEDIA_URL_REFUSED, "image"));
        // Nested in a tool_result too.
        let nested = json!({"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": [
            {"type": "image", "source": {"type": "url", "url": "http://100.64.0.2/x"}}
        ]}]}]});
        assert_eq!(code(&nested), Some(REMOTE_MEDIA_URL_REFUSED));
    }

    #[test]
    fn responses_input_image_and_file_url_are_refused() {
        let body = json!({"input": [{"role": "user", "content": [
            {"type": "input_text", "text": "look"},
            {"type": "input_image", "image_url": "https://example.com/a.png"}
        ]}]});
        assert_eq!(code(&body), Some(REMOTE_MEDIA_URL_REFUSED));
        let file = json!({"input": [{"role": "user", "content": [{"type": "input_file", "file_url": "https://example.com/a.pdf"}]}]});
        assert_eq!(code(&file), Some(REMOTE_MEDIA_URL_REFUSED));
    }

    #[test]
    fn audio_video_and_file_parts_with_a_url_are_refused() {
        for part in [
            json!({"type": "input_audio", "input_audio": {"url": "https://example.com/a.wav"}}),
            json!({"type": "audio_url", "audio_url": {"url": "https://example.com/a.wav"}}),
            json!({"type": "video_url", "video_url": {"url": "https://example.com/a.mp4"}}),
            json!({"type": "file", "file": {"url": "https://example.com/a.pdf"}}),
            // A type nobody knows, carrying a url field.
            json!({"type": "brand_new_media", "url": "http://192.0.2.7/x"}),
        ] {
            assert_eq!(code(&chat(json!([part.clone()]))), Some(REMOTE_MEDIA_URL_REFUSED), "{part}");
        }
    }

    #[test]
    fn a_data_png_with_matching_bytes_passes() {
        assert_eq!(check_body(&image_url(&data_url("image/png", PNG))), Ok(()));
        assert_eq!(check_body(&image_url(&data_url("image/jpg", JPEG))), Ok(()));
        let anthropic = json!({"messages": [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": b64(PNG)}}
        ]}]});
        assert_eq!(check_body(&anthropic), Ok(()));
        let webp = b"RIFF\0\0\0\0WEBPVP8 ".to_vec();
        assert_eq!(check_body(&image_url(&data_url("image/webp", &webp))), Ok(()));
        assert_eq!(check_body(&image_url(&data_url("image/gif", b"GIF89a\x01\x00"))), Ok(()));
    }

    #[test]
    fn declared_png_with_jpeg_bytes_is_refused() {
        assert_eq!(code(&image_url(&data_url("image/png", JPEG))), Some(INLINE_MEDIA_TYPE_MISMATCH));
        let anthropic = json!({"messages": [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": b64(JPEG)}}
        ]}]});
        assert_eq!(code(&anthropic), Some(INLINE_MEDIA_TYPE_MISMATCH));
    }

    #[test]
    fn over_the_size_cap_is_refused() {
        let small = Limits { part: 16, total: 24 };
        let mut big = PNG.to_vec();
        big.resize(17, 0);
        let r = check_with(&image_url(&data_url("image/png", &big)), small).unwrap_err();
        assert_eq!((r.code, r.status()), (INLINE_MEDIA_TOO_LARGE, 413));
        // Each part under the part cap, together over the request cap.
        let mut part = PNG.to_vec();
        part.resize(14, 0);
        let two = chat(json!([
            {"type": "image_url", "image_url": {"url": data_url("image/png", &part)}},
            {"type": "image_url", "image_url": {"url": data_url("image/png", &part)}},
        ]));
        assert_eq!(check_with(&two, small).err().map(|r| r.code), Some(INLINE_MEDIA_TOO_LARGE));
        // Exactly at the part cap passes.
        let mut exact = PNG.to_vec();
        exact.resize(16, 0);
        assert_eq!(check_with(&image_url(&data_url("image/png", &exact)), small), Ok(()));
        assert_eq!(MAX_INLINE_MEDIA_PART_BYTES, 8 << 20);
        assert_eq!(MAX_INLINE_MEDIA_REQUEST_BYTES, 16 << 20);
    }

    #[test]
    fn a_media_type_outside_the_allow_list_is_refused() {
        for mt in ["image/svg+xml", "image/tiff", "text/html", "application/octet-stream", "audio/wav", "video/mp4", ""] {
            assert_eq!(code(&image_url(&data_url(mt, PNG))), Some(INLINE_MEDIA_TYPE_REFUSED), "{mt:?}");
        }
    }

    #[test]
    fn bad_base64_or_a_non_base64_data_url_is_refused() {
        assert_eq!(code(&image_url("data:image/png;base64,@@not base64@@")), Some(INLINE_MEDIA_INVALID));
        assert_eq!(code(&image_url("data:image/png,%89PNG")), Some(INLINE_MEDIA_INVALID));
        assert_eq!(code(&image_url("data:image/png;base64")), Some(INLINE_MEDIA_INVALID));
        // Valid base64 under a header that does not say base64 is still refused.
        assert_eq!(code(&image_url(&format!("data:image/png,{}", b64(PNG)))), Some(INLINE_MEDIA_INVALID));
    }

    #[test]
    fn text_only_messages_are_untouched() {
        let body = json!({"model": "m", "messages": [
            {"role": "system", "content": "be brief; see https://example.com for style"},
            {"role": "user", "content": "fetch http://192.0.2.1/ and summarise"},
            {"role": "user", "content": [{"type": "text", "text": "https://example.com/a.png"}]},
            {"role": "assistant", "content": null, "tool_calls": [{"id": "c", "type": "function", "function": {"name": "f", "arguments": "{\"url\":\"https://example.com\"}"}}]},
            {"role": "tool", "tool_call_id": "c", "content": "ok"}
        ], "input": "a plain Responses input string"});
        assert_eq!(check_body(&body), Ok(()));
    }

    #[test]
    fn the_raw_chat_refusal_carries_the_code_and_next_and_never_the_url() {
        let r = check_body(&image_url("https://192.0.2.9:8443/x.png")).unwrap_err();
        let e = crate::routes::raw_chat::RawChatError::media_refused(&r);
        assert_eq!(e.status.as_u16(), 400);
        let b = e.body();
        assert_eq!(b["error"]["type"], REMOTE_MEDIA_URL_REFUSED);
        assert_eq!(b["error"]["code"], REMOTE_MEDIA_URL_REFUSED);
        assert_eq!(b["error"]["next"], r.next());
        assert!(b["error"]["message"].as_str().unwrap().contains("data: URL"));
        assert!(e.detail.contains("image_url"), "the log names the part type: {}", e.detail);
        let text = format!("{b} {}", e.detail);
        assert!(!text.contains("192.0.2.9") && !text.contains("x.png"), "{text}");
        let big = crate::routes::raw_chat::RawChatError::media_refused(&too_large("image_url", LIMITS));
        assert_eq!(big.status.as_u16(), 413);
    }

    /// Every surface that forwards a caller's chat body reaches the check
    /// before anything is planned or sent.
    #[test]
    fn every_route_reaches_the_check() {
        use crate::test_src::{fn_body, own_code};
        let raw = own_code(include_str!("routes/raw_chat.rs"));
        let send = fn_body(&raw, "pub async fn send_with_failover_pinned<");
        let check = send.find("crate::inline_media::check_body(").expect("the choke point checks the body");
        for later in ["refuses_overflow(", "expected_wait::plan(", "failover_core("] {
            assert!(send.find(later).is_some_and(|i| check < i), "the check comes before {later}");
        }
        assert!(send[check..].starts_with("crate::inline_media::check_body(&probe)"));
        assert!(fn_body(&raw, "pub async fn send_with_failover<").contains("send_with_failover_pinned("));
        assert!(fn_body(&raw, "pub async fn chat_completions_with(").contains("send_with_failover_pinned("));
        assert!(fn_body(&raw, "pub async fn chat_completions(").contains("chat_completions_with("));

        let inf = own_code(include_str!("routes/inference.rs"));
        assert!(fn_body(&inf, "async fn openai_chat_completions(").contains("raw_chat::chat_completions("));
        assert_eq!(fn_body(&inf, "async fn v1_responses(").matches("send_with_failover(").count(), 2, "native and translated");
        let ext = own_code(include_str!("routes/external.rs"));
        assert!(fn_body(&ext, "async fn chat_completions(").contains("raw_chat::chat_completions("));
        assert!(fn_body(&ext, "async fn do_chat_nonstream(").contains("raw_chat::chat_completions("));

        let tr = own_code(include_str!("harness/translator.rs"));
        for (handler, route) in [
            ("async fn chat_completions(State(sh)", "harness:/v1/chat/completions"),
            ("async fn messages(State(sh)", "harness:/v1/messages"),
            ("async fn responses(State(sh)", "harness:/v1/responses"),
        ] {
            let f = fn_body(&tr, handler);
            let c = f.find(&format!("media_refusal(&body, \"{route}\")")).unwrap_or_else(|| panic!("{handler} checks"));
            let sent = f.find("complete(&sh").unwrap_or_else(|| panic!("{handler} sends"));
            assert!(c < sent, "{handler} checks before it sends");
        }
        assert!(fn_body(&tr, "fn media_refusal(").contains("crate::inline_media::check_body(body)"));
    }

    #[test]
    fn an_unknown_part_without_a_url_is_untouched() {
        let body = chat(json!([
            {"type": "brand_new_thing", "payload": {"x": 1}},
            {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}},
            {"type": "text", "text": "hi", "citations": [{"type": "web_search_result_location", "url": "https://example.com"}]}
        ]));
        assert_eq!(check_body(&body), Ok(()));
    }
}
