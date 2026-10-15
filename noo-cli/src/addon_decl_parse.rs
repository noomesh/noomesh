// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Parse and validate one overlay's top-level `x-noo-addon` block.
//!
//! Shared, by `#[path]`, between build.rs (the overlays that ship in this
//! tree) and the CLI at run time (an add-on's overlay that arrived in its
//! signed bundle, `crate::commands::secrets::addon_decls`), so both read
//! the block by the same rules. Depends on `serde_yaml` only, which is all
//! a build script has.
//!
//! Vocabulary (is each scope one the gateway issues?) is NOT checked here:
//! the vocabulary lives in gateway-rust, and `provision` asks the gateway
//! before minting.

/// One overlay's `x-noo-addon`, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDecl {
    pub addon: String,
    pub consumer: String,
    pub key: String,
    pub containers: Vec<String>,
    pub scopes: Vec<String>,
    pub why: Option<String>,
}

/// The block in `text`, `Ok(None)` when the overlay declares none, `Err`
/// naming `label` when it is malformed. `expect_addon`, when given, is the
/// add-on key the file belongs to (its name, or the bundle directory it was
/// materialised into); the block must name the same one.
pub fn parse_decl(label: &str, text: &str, expect_addon: Option<&str>) -> Result<Option<ParsedDecl>, String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| format!("{label}: not valid YAML ({e})"))?;
    let Some(block) = doc.get("x-noo-addon") else { return Ok(None) };
    let refuse = |what: &str| format!("{label}: x-noo-addon {what}");
    let s = |k: &str| -> Result<String, String> {
        block.get(k).and_then(|v| v.as_str()).map(str::to_string).ok_or_else(|| refuse(&format!("needs a string `{k}`")))
    };
    let list = |k: &str| -> Result<Vec<String>, String> {
        let seq = block.get(k).and_then(|v| v.as_sequence()).ok_or_else(|| refuse(&format!("needs a list `{k}`")))?;
        seq.iter()
            .map(|v| v.as_str().map(str::to_string).ok_or_else(|| refuse(&format!("`{k}` holds a non-string"))))
            .collect()
    };
    let d = ParsedDecl {
        addon: s("addon")?,
        consumer: s("consumer")?,
        key: s("key")?,
        containers: list("containers")?,
        scopes: list("scopes")?,
        why: block.get("why").and_then(|v| v.as_str()).map(|w| w.trim().to_string()),
    };
    if let Some(want) = expect_addon {
        if d.addon != want {
            return Err(refuse(&format!("addon `{}` does not match the file it is declared in ({want})", d.addon)));
        }
    }
    let Some(suffix) = d.key.strip_prefix("NOO_SVC_KEY_") else { return Err(refuse("key must be NOO_SVC_KEY_*")) };
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
        return Err(refuse("key must match ^NOO_SVC_KEY_[A-Z0-9_]+$"));
    }
    // The consumer is what provision_targets has always derived from the key;
    // declaring it lets a grep for `svc:evolve` land here, and the parser
    // insists the two agree rather than choosing one.
    if d.consumer != format!("svc:{}", suffix.to_ascii_lowercase().replace('_', "-")) {
        return Err(refuse(&format!("consumer `{}` is not svc:<kebab of the key suffix>", d.consumer)));
    }
    if d.containers.is_empty() || d.containers.iter().any(|c| !c.starts_with("noo-")) {
        return Err(refuse("containers must be a non-empty list of noo-* names"));
    }
    if d.scopes.is_empty() {
        return Err(refuse("scopes must not be empty"));
    }
    for s in &d.scopes {
        if matches!(s.as_str(), "addon" | "kiosk" | "mcp:operator" | "identity") {
            return Err(refuse(&format!(
                "may not ask for `{s}` (addon is always added; the rest are not add-on scopes)"
            )));
        }
    }
    Ok(Some(d))
}

/// The add-on key a core overlay's file name belongs to:
/// `docker-compose.trellion.yml` → `trellion` (`-` read as `_`). build.rs
/// is its caller.
#[allow(dead_code)]
pub fn addon_of_overlay_name(file: &str) -> Option<String> {
    let mid = file.strip_prefix("docker-compose.")?.strip_suffix(".yml")?;
    (!mid.is_empty()).then(|| mid.replace('-', "_"))
}
