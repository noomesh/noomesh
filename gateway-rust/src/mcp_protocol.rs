// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! MCP wire protocol shared by both doors — the part that is about WHICH
//! REVISION the client speaks, not WHO the client is.
//!
//! The doors are dual-era (spec 2026-07-28, "Backward
//! Compatibility with Initialization-Based Versions"):
//!
//! - **Modern** (`2026-07-28`): no handshake. Every request carries its
//!   protocol version in `params._meta`, mirrored into the
//!   `MCP-Protocol-Version` header, plus `Mcp-Method` / `Mcp-Name` headers
//!   that MUST match the body. Results carry `resultType`, list results
//!   carry cache hints, `server/discover` is mandatory, `ping` and
//!   `initialize` are gone, and an unknown method is an HTTP 404.
//! - **Legacy** (`2025-11-25` and earlier): the `initialize` handshake, no
//!   `_meta`, plain JSON-RPC `-32601` for unknown methods. Every harness
//!   configured before the spec landed speaks this, so it stays byte-for-byte
//!   what it was.
//!
//! The era is a property of the REQUEST: modern `_meta` present → modern,
//! otherwise legacy. That is exactly the selector the spec gives a dual-era
//! server. Nothing here holds state between requests — both doors were
//! stateless before the spec made it mandatory, which is why this is a
//! surface change and not an architecture change.

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine as _;
use serde_json::{json, Value};

use crate::mcp_external::RpcRequest;

/// Modern revisions this gateway serves. Order is the preference order
/// advertised to clients.
pub(crate) const SUPPORTED_MODERN: &[&str] = &["2026-07-28"];

/// The revision legacy `initialize` echoes. Unchanged from the Python hub
/// so existing clients negotiate exactly as before.
pub(crate) const LEGACY_VERSION: &str = "2024-11-05";

const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// JSON-RPC error codes from the spec-reserved range Codes).
pub(crate) const ERR_HEADER_MISMATCH: i32 = -32020;
pub(crate) const ERR_UNSUPPORTED_VERSION: i32 = -32022;
pub(crate) const ERR_METHOD_NOT_FOUND: i32 = -32601;

/// Freshness hint on modern list results. The catalog is compiled in and
/// changes only with a gateway deploy, so an hour is conservative.
const LIST_TTL_MS: u64 = 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Era {
    Legacy,
    Modern,
}

impl Era {
    /// For logs and audit rows, so "which revision does this client speak"
    /// is answered by the gateway rather than by a client's debug log.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Era::Legacy => "legacy",
            Era::Modern => "2026-07-28",
        }
    }
}

/// A parsed, era-classified, header-validated request. Construct with
/// [`parse`]; the door then matches on `req.method` and answers through
/// the shaping helpers so the reply matches the era it was asked in.
#[derive(Debug)]
pub(crate) struct Envelope {
    pub(crate) req: RpcRequest,
    pub(crate) era: Era,
}

/// Parse the body and classify + validate it. Errors are complete HTTP
/// responses in the shape the requesting era expects, so the door just
/// returns them.
pub(crate) fn parse(door: Door, headers: &HeaderMap, body: &[u8]) -> Result<Envelope, Response> {
    check_origin(door, headers)?;
    check_content_type(headers)?;

    let req: RpcRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return Err(rpc_error(Value::Null, -32700, &format!("parse error: {e}"))),
    };

    let meta_version = req
        .params
        .get("_meta")
        .and_then(|m| m.get(META_VERSION))
        .and_then(Value::as_str)
        .map(str::to_string);

    let header_version = header(headers, "mcp-protocol-version");

    let Some(requested) = meta_version else {
        // No modern `_meta`. A header naming a MODERN revision without the
        // body's `_meta` is a malformed modern request, not a legacy one —
        // fail it the way the spec's server-validation section says, so a
        // client half-way through an upgrade gets a diagnosable error
        // rather than legacy semantics it did not ask for.
        if let Some(hv) = &header_version {
            if SUPPORTED_MODERN.contains(&hv.as_str()) {
                return Err(modern_error(
                    StatusCode::BAD_REQUEST,
                    req.id,
                    ERR_HEADER_MISMATCH,
                    &format!(
                        "MCP-Protocol-Version header is {hv} but the request body carries no params._meta.{META_VERSION}"
                    ),
                    None,
                ));
            }
        }
        return Ok(Envelope { req, era: Era::Legacy });
    };

    // From here on the request declares itself modern.
    if !SUPPORTED_MODERN.contains(&requested.as_str()) {
        return Err(modern_error(
            StatusCode::BAD_REQUEST,
            req.id,
            ERR_UNSUPPORTED_VERSION,
            "Unsupported protocol version",
            Some(json!({ "supported": SUPPORTED_MODERN, "requested": requested })),
        ));
    }
    match header_version.as_deref() {
        Some(hv) if hv == requested => {}
        Some(hv) => {
            return Err(header_mismatch(
                req.id,
                &format!("MCP-Protocol-Version header value '{hv}' does not match body value '{requested}'"),
            ))
        }
        None => {
            return Err(header_mismatch(
                req.id,
                "MCP-Protocol-Version header is required on a 2026-07-28 request",
            ))
        }
    }

    // Notifications: the transport defines no header requirements for a
    // notification POST, so only requests are held to Mcp-Method/Mcp-Name.
    if req.method.starts_with("notifications/") {
        return Ok(Envelope { req, era: Era::Modern });
    }

    match header(headers, "mcp-method") {
        Some(m) if m == req.method => {}
        Some(m) => {
            return Err(header_mismatch(
                req.id,
                &format!("Mcp-Method header value '{m}' does not match body value '{}'", req.method),
            ))
        }
        None => return Err(header_mismatch(req.id, "Mcp-Method header is required")),
    }

    if req.method == "tools/call" {
        let body_name = req.params.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
        match header(headers, "mcp-name").map(|v| decode_sentinel(&v)) {
            Some(Ok(n)) if n == body_name => {}
            Some(Ok(n)) => {
                return Err(header_mismatch(
                    req.id,
                    &format!("Mcp-Name header value '{n}' does not match body value '{body_name}'"),
                ))
            }
            Some(Err(why)) => return Err(header_mismatch(req.id, &format!("Mcp-Name header: {why}"))),
            None => return Err(header_mismatch(req.id, "Mcp-Name header is required for tools/call")),
        }
    }

    Ok(Envelope { req, era: Era::Modern })
}

impl Envelope {
    /// A `resultType: "complete"` result, stamped with `serverInfo` for
    /// modern callers; the bare result object for legacy ones (byte-identical
    /// to what those clients always received).
    pub(crate) fn result(&self, mut result: Value, server_name: &str) -> Response {
        if self.era == Era::Modern {
            if let Some(obj) = result.as_object_mut() {
                obj.insert("resultType".into(), json!("complete"));
                let meta = obj.entry("_meta").or_insert_with(|| json!({}));
                if let Some(meta) = meta.as_object_mut() {
                    meta.insert(META_SERVER_INFO.into(), server_info(server_name));
                }
            }
        }
        rpc_result(self.req.id.clone(), result)
    }

    /// `tools/list`. Modern results are cacheable and say so; `private`
    /// because every door authenticates, so a shared intermediary must not
    /// serve one caller's catalog to another.
    pub(crate) fn tools_list(&self, tools: Value, server_name: &str) -> Response {
        let mut r = json!({ "tools": tools });
        if self.era == Era::Modern {
            r["ttlMs"] = json!(LIST_TTL_MS);
            r["cacheScope"] = json!("private");
        }
        self.result(r, server_name)
    }

    /// `server/discover` — mandatory for modern servers; served in both
    /// eras because a dual-era client may probe with it before choosing.
    pub(crate) fn discover(&self, server_name: &str, instructions: &str) -> Response {
        let r = json!({
            "supportedVersions": SUPPORTED_MODERN,
            "capabilities": { "tools": { "listChanged": false } },
            "instructions": instructions,
            "ttlMs": LIST_TTL_MS,
            "cacheScope": "private",
        });
        // Always modern-shaped: the result type is defined only by the
        // modern spec and a legacy client asking for it is by definition
        // upgrading.
        let mut r = r;
        r["resultType"] = json!("complete");
        r["_meta"] = json!({ META_SERVER_INFO: server_info(server_name) });
        rpc_result(self.req.id.clone(), r)
    }

    /// Legacy `initialize`. On a MODERN request the handshake does not exist:
    /// a `-32601` naming the versions we do speak, which the spec asks for so
    /// a legacy client with no fall-forward path at least sees why.
    pub(crate) fn initialize(&self, server_name: &str) -> Response {
        match self.era {
            Era::Legacy => rpc_result(
                self.req.id.clone(),
                // `listChanged`: a session opened under another catalogue
                // is sent `notifications/tools/list_changed` on its next
                // answered request (`mcp_session::with_list_changed`).
                json!({
                    "protocolVersion": LEGACY_VERSION,
                    "capabilities": {"tools": {"listChanged": true}},
                    "serverInfo": server_info(server_name),
                }),
            ),
            Era::Modern => self.method_not_found(),
        }
    }

    /// `ping` exists only in the legacy revision.
    pub(crate) fn ping(&self) -> Response {
        match self.era {
            Era::Legacy => rpc_result(self.req.id.clone(), json!({})),
            Era::Modern => self.method_not_found(),
        }
    }

    /// Unknown method: modern = HTTP 404 with the JSON-RPC error (the status
    /// is what distinguishes "this endpoint exists but not that method" from
    /// a legacy HTTP+SSE server's 404); legacy = 200 with the error object.
    pub(crate) fn method_not_found(&self) -> Response {
        let msg = format!(
            "method not found: {} (supported protocol versions: {})",
            self.req.method,
            SUPPORTED_MODERN.join(", ")
        );
        match self.era {
            Era::Modern => modern_error(
                StatusCode::NOT_FOUND,
                self.req.id.clone(),
                ERR_METHOD_NOT_FOUND,
                &msg,
                None,
            ),
            Era::Legacy => rpc_error(self.req.id.clone(), ERR_METHOD_NOT_FOUND, &msg),
        }
    }
}

fn server_info(name: &str) -> Value {
    json!({ "name": name, "version": env!("CARGO_PKG_VERSION") })
}

/// GET / DELETE on an MCP endpoint: the legacy standalone SSE stream and
/// session teardown. This revision has neither; the spec says 405.
pub(crate) async fn method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(axum::http::header::ALLOW, "POST")],
        Json(json!({
            "jsonrpc": "2.0", "id": null,
            "error": {
                "code": ERR_METHOD_NOT_FOUND,
                "message": "this MCP endpoint accepts POST only: no GET stream and no sessions (spec 2026-07-28)",
            },
        })),
    )
        .into_response()
}

/// Which listener a request arrived on. There is one: the gateway's HTTPS
/// port. The enum stays because the DNS-rebinding rule is written per
/// door, and a second listener (there was a loopback one until
/// stack-v0.2.40, with its own stricter rule) would need its own variant
/// and its own rule rather than a bool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Door {
    /// A door on the shared HTTPS listener (`/mcp/user`, `/mcp/operator`),
    /// reached by the gateway's real hostname and always carrying a
    /// credential of its own.
    Tls,
}

/// The authority in an origin (`scheme://host[:port]`).
fn origin_authority(origin: &str) -> &str {
    origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(origin)
        .trim_end_matches('/')
}

/// DNS-rebinding guard & Endpoint).
///
/// On the **TLS** doors the rule is `Origin` must name the same authority as
/// `Host`: those doors are reached by the gateway's real name and always
/// authenticate their own bearer, so `Host` is a fair statement of "this
/// gateway" and needs no configuration.
///
/// The loopback listener that existed until stack-v0.2.40 needed a stricter
/// rule (there a rebinding page controls both `Host` and `Origin`, and the
/// door's token was optional, so `Host` itself had to be a loopback name).
/// That listener is gone; every door now carries a credential, and the
/// comparison above is the whole guard. A second listener would bring its
/// own `Door` variant and its own rule back here.
fn check_origin(door: Door, headers: &HeaderMap) -> Result<(), Response> {
    let origin = header(headers, "origin");
    let host = header(headers, "host").unwrap_or_default();

    let Door::Tls = door;

    let Some(origin) = origin else { return Ok(()) };
    if origin.eq_ignore_ascii_case("null") {
        return Err(origin_forbidden(&origin));
    }
    let origin_host = origin_authority(&origin);
    if !host.is_empty() && origin_host.eq_ignore_ascii_case(&host) {
        Ok(())
    } else {
        Err(origin_forbidden(&origin))
    }
}

/// JSON-RPC over HTTP is JSON. Requiring the type stops a cross-origin
/// form POST (`text/plain`, `multipart/form-data` — the three types a form
/// can send without a CORS preflight) from reaching a tool call: those
/// requests never get a preflight, so the browser sends them whatever the
/// server's CORS policy says.
fn check_content_type(headers: &HeaderMap) -> Result<(), Response> {
    let ct = header(headers, "content-type").unwrap_or_default();
    let base = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if base == "application/json" {
        Ok(())
    } else {
        Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(json!({
                "jsonrpc": "2.0", "id": null,
                "error": {
                    "code": -32000,
                    "message": format!(
                        "this MCP endpoint requires Content-Type: application/json (got '{}')",
                        if ct.is_empty() { "none" } else { ct.as_str() }
                    ),
                },
            })),
        )
            .into_response())
    }
}

fn origin_forbidden(origin: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "jsonrpc": "2.0", "id": null,
            "error": { "code": -32000, "message": format!("Origin '{origin}' is not this gateway") },
        })),
    )
        .into_response()
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// `=?base64?…?=` sentinel decoding for `Mcp-Name` Encoding).
fn decode_sentinel(v: &str) -> Result<String, String> {
    let Some(inner) = v.strip_prefix("=?base64?").and_then(|s| s.strip_suffix("?=")) else {
        return Ok(v.to_string());
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(inner)
        .map_err(|e| format!("invalid base64 sentinel: {e}"))?;
    String::from_utf8(bytes).map_err(|_| "base64 sentinel is not UTF-8".to_string())
}

fn header_mismatch(id: Value, msg: &str) -> Response {
    modern_error(StatusCode::BAD_REQUEST, id, ERR_HEADER_MISMATCH, &format!("Header mismatch: {msg}"), None)
}

/// A JSON-RPC error object under a NON-200 status — the modern spec ties
/// transport status to the error class (400 validation, 404 unknown method).
pub(crate) fn modern_error(status: StatusCode, id: Value, code: i32, message: &str, data: Option<Value>) -> Response {
    let mut err = json!({ "code": code, "message": message });
    if let Some(d) = data {
        err["data"] = d;
    }
    (status, Json(json!({ "jsonrpc": "2.0", "id": id, "error": err }))).into_response()
}

pub(crate) fn rpc_result(id: Value, result: Value) -> Response {
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

pub(crate) fn rpc_error(id: Value, code: i32, message: &str) -> Response {
    Json(json!({
        "jsonrpc": "2.0", "id": id,
        "error": {"code": code, "message": message},
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    /// Every pre-existing test speaks the TLS door with a JSON body — the
    /// two things `parse` now takes explicitly.
    fn parse_tls(headers: &HeaderMap, body: &[u8]) -> Result<Envelope, Response> {
        let mut h = headers.clone();
        if !h.contains_key("content-type") {
            h.insert("content-type", "application/json".parse().unwrap());
        }
        parse(Door::Tls, &h, body)
    }

    fn modern_body(method: &str, extra: Value) -> Vec<u8> {
        let mut params = json!({ "_meta": { META_VERSION: "2026-07-28" } });
        if let Some(o) = extra.as_object() {
            for (k, v) in o {
                params[k] = v.clone();
            }
        }
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
            .to_string()
            .into_bytes()
    }

    async fn body_json(resp: Response) -> (StatusCode, Value) {
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    #[test]
    fn a_request_without_meta_is_legacy() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let env = parse_tls(&HeaderMap::new(), body).unwrap();
        assert_eq!(env.era, Era::Legacy);
        // A 2025-06-18-era client sends the header but no _meta: still legacy.
        let env = parse_tls(&hm(&[("mcp-protocol-version", "2025-06-18")]), body).unwrap();
        assert_eq!(env.era, Era::Legacy);
    }

    #[tokio::test]
    async fn modern_header_without_meta_is_a_header_mismatch() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        let err = parse_tls(&hm(&[("mcp-protocol-version", "2026-07-28")]), body).unwrap_err();
        let (status, v) = body_json(err).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(v["error"]["code"], ERR_HEADER_MISMATCH);
    }

    #[tokio::test]
    async fn unsupported_version_lists_supported() {
        let body = json!({"jsonrpc":"2.0","id":7,"method":"tools/list",
            "params":{"_meta":{META_VERSION:"1900-01-01"}}}).to_string();
        let err = parse_tls(&hm(&[("mcp-protocol-version", "1900-01-01")]), body.as_bytes()).unwrap_err();
        let (status, v) = body_json(err).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(v["error"]["code"], ERR_UNSUPPORTED_VERSION);
        assert_eq!(v["error"]["data"]["supported"], json!(SUPPORTED_MODERN));
        assert_eq!(v["error"]["data"]["requested"], "1900-01-01");
        assert_eq!(v["id"], 7);
    }

    #[tokio::test]
    async fn modern_requires_matching_headers() {
        let body = modern_body("tools/call", json!({"name": "noo_status", "arguments": {}}));
        // No headers at all.
        let (s, v) = body_json(parse_tls(&HeaderMap::new(), &body).unwrap_err()).await;
        assert_eq!((s, v["error"]["code"].clone()), (StatusCode::BAD_REQUEST, json!(ERR_HEADER_MISMATCH)));
        // Version ok, method missing.
        let h = hm(&[("mcp-protocol-version", "2026-07-28")]);
        let (_, v) = body_json(parse_tls(&h, &body).unwrap_err()).await;
        assert!(v["error"]["message"].as_str().unwrap().contains("Mcp-Method"));
        // Method wrong.
        let h = hm(&[("mcp-protocol-version", "2026-07-28"), ("mcp-method", "tools/list")]);
        let (_, v) = body_json(parse_tls(&h, &body).unwrap_err()).await;
        assert!(v["error"]["message"].as_str().unwrap().contains("does not match"));
        // Name missing for tools/call.
        let h = hm(&[("mcp-protocol-version", "2026-07-28"), ("mcp-method", "tools/call")]);
        let (_, v) = body_json(parse_tls(&h, &body).unwrap_err()).await;
        assert!(v["error"]["message"].as_str().unwrap().contains("Mcp-Name"));
        // All present and matching.
        let h = hm(&[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", "noo_status"),
        ]);
        let env = parse_tls(&h, &body).unwrap();
        assert_eq!(env.era, Era::Modern);
        assert_eq!(env.req.method, "tools/call");
    }

    #[test]
    fn mcp_name_accepts_the_base64_sentinel() {
        let body = modern_body("tools/call", json!({"name": "Hello, 世界", "arguments": {}}));
        let h = hm(&[
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", "=?base64?SGVsbG8sIOS4lueVjA==?="),
        ]);
        assert!(parse_tls(&h, &body).is_ok());
        assert_eq!(decode_sentinel("plain").unwrap(), "plain");
        assert!(decode_sentinel("=?base64?!!!?=").is_err());
    }

    #[test]
    fn modern_notifications_need_no_method_headers() {
        let body = modern_body("notifications/cancelled", json!({}));
        let h = hm(&[("mcp-protocol-version", "2026-07-28")]);
        assert_eq!(parse_tls(&h, &body).unwrap().era, Era::Modern);
    }

    #[tokio::test]
    async fn origin_must_be_this_gateway_when_present() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        assert!(parse_tls(&hm(&[("host", "gw.example:8080")]), body).is_ok());
        assert!(parse_tls(&hm(&[("host", "gw.example:8080"), ("origin", "https://gw.example:8080")]), body).is_ok());
        for bad in ["https://evil.example", "null", "https://gw.example:9999"] {
            let err = parse_tls(&hm(&[("host", "gw.example:8080"), ("origin", bad)]), body).unwrap_err();
            assert_eq!(err.status(), StatusCode::FORBIDDEN, "{bad}");
        }
    }

    fn rpc() -> &'static [u8] {
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#
    }

    fn json_hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = hm(pairs);
        h.insert("content-type", "application/json".parse().unwrap());
        h
    }

    /// `text/plain`, `multipart/form-data` and `application/x-www-form-urlencoded`
    /// are the types a cross-origin HTML form can POST with no preflight.
    #[test]
    fn a_tool_call_must_be_declared_json() {
        for door in [Door::Tls] {
            let host = "gw.example:8080";
            for ct in ["text/plain", "multipart/form-data", "application/x-www-form-urlencoded"] {
                let h = hm(&[("host", host), ("content-type", ct)]);
                assert_eq!(
                    parse(door, &h, rpc()).unwrap_err().status(),
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "{ct} on {door:?}"
                );
            }
            // Missing entirely is refused too; a charset parameter is fine.
            assert_eq!(
                parse(door, &hm(&[("host", host)]), rpc()).unwrap_err().status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE
            );
            let h = hm(&[("host", host), ("content-type", "application/json; charset=utf-8")]);
            assert!(parse(door, &h, rpc()).is_ok());
        }
    }


    #[tokio::test]
    async fn results_are_shaped_per_era() {
        let legacy = parse_tls(&HeaderMap::new(), br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#).unwrap();
        let (_, v) = body_json(legacy.tools_list(json!([]), "t")).await;
        assert!(v["result"].get("resultType").is_none(), "legacy result must be byte-compatible");
        assert!(v["result"].get("ttlMs").is_none());

        let modern = parse_tls(
            &hm(&[("mcp-protocol-version", "2026-07-28"), ("mcp-method", "tools/list")]),
            &modern_body("tools/list", json!({})),
        )
        .unwrap();
        let (_, v) = body_json(modern.tools_list(json!([]), "t")).await;
        assert_eq!(v["result"]["resultType"], "complete");
        assert_eq!(v["result"]["cacheScope"], "private");
        assert!(v["result"]["ttlMs"].as_u64().unwrap() > 0);
        assert_eq!(v["result"]["_meta"][META_SERVER_INFO]["name"], "t");

        // Modern has no handshake and no ping; the refusal names what we speak.
        let (s, v) = body_json(modern.initialize("t")).await;
        assert_eq!((s, v["error"]["code"].clone()), (StatusCode::NOT_FOUND, json!(ERR_METHOD_NOT_FOUND)));
        assert!(v["error"]["message"].as_str().unwrap().contains("2026-07-28"));
        assert_eq!(modern.ping().status(), StatusCode::NOT_FOUND);
        // Legacy keeps both, at 200.
        assert_eq!(legacy.initialize("t").status(), StatusCode::OK);
        let (_, v) = body_json(legacy.initialize("t")).await;
        assert_eq!(v["result"]["protocolVersion"], LEGACY_VERSION);
        assert_eq!(legacy.ping().status(), StatusCode::OK);
        assert_eq!(legacy.method_not_found().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn discover_is_served_in_both_eras() {
        let legacy = parse_tls(&HeaderMap::new(), br#"{"jsonrpc":"2.0","id":"d","method":"server/discover","params":{}}"#).unwrap();
        let (s, v) = body_json(legacy.discover("t", "hi")).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["result"]["supportedVersions"], json!(SUPPORTED_MODERN));
        assert_eq!(v["result"]["resultType"], "complete");
        assert_eq!(v["result"]["capabilities"]["tools"]["listChanged"], false);
        assert_eq!(v["id"], "d");
    }

    /// A legacy session is told when the catalogue moves under it
    /// (`mcp_session::with_list_changed`), so legacy initialize says it may
    /// be. A modern client has no session to tell: discover keeps `false`.
    #[tokio::test]
    async fn legacy_initialize_advertises_list_changed_and_discover_does_not() {
        let legacy = parse_tls(&HeaderMap::new(), br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#).unwrap();
        let (s, v) = body_json(legacy.initialize("t")).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["result"]["capabilities"]["tools"]["listChanged"], true);
        let (_, d) = body_json(legacy.discover("t", "hi")).await;
        assert_eq!(d["result"]["capabilities"]["tools"]["listChanged"], false);
    }

    #[tokio::test]
    async fn get_and_delete_are_405_with_allow_post() {
        let r = method_not_allowed().await;
        assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(r.headers()[axum::http::header::ALLOW], "POST");
    }
}
