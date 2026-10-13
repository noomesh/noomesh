// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Output + exit-code contract for native commands.
//!
//! Exit codes are part of the agent API — scripts branch on them instead of
//! parsing prose. Keep in sync with the table in main.rs and NOO_CLI.md.

#[derive(Clone, Copy)]
#[allow(dead_code)] // Ok/Generic document the full contract even before a handler uses them
pub enum ExitCode {
    Ok = 0,
    Generic = 1,
    Usage = 2,
    GatewayUnreachable = 3,
    AuthFailed = 4,
    RemoteError = 5,
}

/// Print an error (JSON on stderr in json mode, human text otherwise) and exit.
pub fn fail(json: bool, code: ExitCode, kind: &str, msg: &str, hint: Option<&str>) -> ! {
    if json {
        let mut obj = serde_json::json!({ "error": msg, "code": kind });
        if let Some(h) = hint {
            obj["hint"] = serde_json::Value::String(h.to_string());
        }
        eprintln!("{obj}");
    } else {
        crate::ui::failed(msg, hint);
    }
    crate::ui::pager_finish();
    std::process::exit(code as i32);
}
