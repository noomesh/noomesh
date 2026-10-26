// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Centralized file path resolution.
//!
//! All hardcoded path candidates live here instead of being scattered
//! across config.rs, coordinator.rs, settings.rs, ui.rs, etc.
//! Each location lists Docker-container paths first, then local-dev
//! fallbacks.  `resolve()` returns the first candidate that exists.

use std::path::{Path, PathBuf};

// ═══════════════════════════════════════════════════════════════
// Path candidate lists
// ═══════════════════════════════════════════════════════════════

/// noomesh.yaml — runtime config (Docker, then local).
pub const CONFIG_YAML_CANDIDATES: &[&str] = &["/app/noomesh.yaml", "noomesh.yaml"];

/// config/tools.json — tool schemas + NATS subjects.
pub const TOOLS_JSON_CANDIDATES: &[&str] = &["/app/config/tools.json", "config/tools.json"];

/// Fallback static file directory.
pub const STATIC_DIR: &str = "/app/static";

/// The versioned mesh-UI artifact tree (Phase 5). Populated by the gateway
/// The dashboard artifact, unpacked by the Dockerfile's
/// `COPY --from=ui /dist /var/www`: `index.html` plus hashed `assets/`.
/// This is the ONLY dashboard source. The vendored console and the
/// NOO_UI_SOURCE selector that chose between them are retired and
/// removed from the tree.
pub const UI_WWW_DIR: &str = "/var/www";

// PYTHON_SRC and PROMPT_SKILLS_DIR used to live here, pointing at /app/src.
// Both were removed with the Python source tree itself: the gateway image no
// longer copies src/, and neither constant had a single consumer anywhere in
// gateway-rust. A path constant for a directory that does not exist is worse
// than no constant — the next reader assumes something reads it.
// Prompt-skill templates are owned by noo-trellion, which does carry the
// Python tree.

/// Bootstrap-token enrollment script, served publicly at
/// GET /bootstrap so `noo cluster bootstrap-token create` one-liners work
/// against the gateway itself. (The pre-token `/bootstrap-node.sh` it once
/// sat beside was removed 2026-09-27.)
pub const BOOTSTRAP_ENROLL_SCRIPT_CANDIDATES: &[&str] =
    &["/app/scripts/bootstrap-enroll.sh", "scripts/bootstrap-enroll.sh"];

/// The ROOT host-prep phase, served at GET /bootstrap/prep and
/// sudo-run by bootstrap-enroll.sh during the operator's one attended
/// escalation — so machine prep happens at birth and no standing grant
/// broader than the revive verb is ever needed afterwards.
pub const BOOTSTRAP_PREP_SCRIPT_CANDIDATES: &[&str] =
    &["/app/scripts/prep-host.sh", "scripts/prep-host.sh"];

/// noo-apply: the CA-signature-gated root applier,
/// fetched by prep-host.sh. (Its sibling noo-gate is no longer served.)
pub const BOOTSTRAP_APPLY_SCRIPT_CANDIDATES: &[&str] =
    &["/app/scripts/noo-apply.sh", "scripts/noo-apply.sh"];
pub const BOOTSTRAP_DEENROLL_SCRIPT_CANDIDATES: &[&str] =
    &["/app/scripts/deenroll-node-local.sh", "scripts/deenroll-node-local.sh"];

/// The pull-provisioning fetcher: installed on nodes by
/// prep-host.sh as /usr/local/bin/noo-fetch; polls /bootstrap/bundle.
pub const BOOTSTRAP_FETCH_SCRIPT_CANDIDATES: &[&str] =
    &["/app/scripts/noo-fetch.sh", "scripts/noo-fetch.sh"];

// ═══════════════════════════════════════════════════════════════
// Resolver
// ═══════════════════════════════════════════════════════════════

/// Return the first candidate path that exists on disk.
pub fn resolve(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .map(PathBuf::from)
}
