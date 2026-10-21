// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Native command handlers, one file per command group. Each handler:
//! parse its own args (returning `Err(Unhandled)` on anything unrecognized
//! so the Python CLI serves it), fetch, then `--json` prints the raw gateway
//! JSON, otherwise a compact human rendering. Data to stdout, diagnostics to
//! stderr, exit code per the contract in output.rs.

pub mod addons;
pub mod channel;
pub mod addon_enable;
pub mod addon_pins;
pub mod backups;
pub mod agents;
pub mod approval;
pub mod auth;
pub mod autonomy;
pub mod channels;
pub mod chat;
pub mod browser;
pub mod bundle;
pub mod cluster;
pub mod cluster_provision;
pub mod cluster_host_telemetry;
pub mod cluster_vendor;
pub mod node_vendor;
pub mod cluster_push_secrets;
pub mod cluster_gpu;
pub mod cluster_profile;
pub mod cluster_verify;
pub mod image_stage;
pub mod cluster_class;
pub mod cluster_embedding_space;
pub mod cluster_tune;
pub mod db;
pub mod entitlement;
#[cfg(has_entitlement_signer)]
pub mod entitlement_signer;
pub mod release_sign;
pub mod addon_lock_cmd;
pub mod doctor;
pub mod tailnet_policy;
pub(crate) mod tailnet_merge;
pub mod enroll;
pub mod config;
pub mod launch_render;
pub mod bind_sources;
pub mod grafana_door;
pub mod graph;
pub mod walks;
pub mod health;
pub mod heartbeat;
pub mod inference;
pub mod jobs;
pub mod kiosk;
pub mod kiosk_seat;
pub mod logs;
pub mod mcp;
pub mod memory;
pub mod mesh;
pub mod nats_users;
pub mod controller;
pub mod migrate;
pub mod models;
pub mod models_fetch;
pub mod voice_models;
pub mod pki;
pub mod plugins;
pub mod proactive;
pub mod prompt_skills;
pub mod rag;
pub mod security;
pub mod secrets;
pub mod secrets_remove;
pub mod secrets_reveal;
pub mod plaintext_env;
pub mod secrets_delivery;
pub mod container_files;
pub mod offboard;
pub mod provision;
pub mod security_local;
pub mod security_scan_node;
pub mod skills;
pub mod stack_db_compat;
pub mod systems;
pub mod test;
pub mod tools;
pub mod upgrade;
pub mod usage;
pub mod recall;
pub mod voice;
pub mod workflow;
pub mod tasks;

pub use agents::{
    agents_collaborate, agents_inbox, agents_list, agents_messages, agents_peer_card, agents_peer_dispatch, agents_peer_list,
    agents_presence, agents_send, agents_thread,
};
pub use auth::{auth_login, auth_logout, auth_status};
pub use tasks::{tasks_answer, tasks_create, tasks_list, tasks_resubmit, tasks_show, tasks_stop};
pub use approval::{approval_approve, approval_deny, approval_list, approval_stats, approval_status};
pub use autonomy::{
    autonomy_audit, autonomy_decisions, autonomy_disable, autonomy_enable, autonomy_status,
};
pub use channels::{channels_export, channels_import, channels_status, channels_test};
pub use chat::chat;
pub use nats_users::{cluster_nats_creds_rotate, cluster_nats_users_render};
pub use cluster::{
    cluster_add_companion, cluster_add_monitor, cluster_assign, cluster_clean_node,
    cluster_clear_cooldowns, cluster_desired, cluster_down, cluster_fit, cluster_proposals, cluster_forget, cluster_init_secret,
    cluster_logs, cluster_show, cluster_place, cluster_restart_agent, cluster_maintenance,
    cluster_scale, cluster_set_config, cluster_status, cluster_sync_model_files,
    cluster_exec, cluster_reconnect, cluster_sync_models, cluster_unplace, cluster_up,
};
pub use browser::{browser_open, browser_status, browser_stop};
pub use image_stage::cluster_stage_images;
pub use cluster_provision::{
    cluster_invite,
    cluster_auto_place, cluster_bootstrap_token_create,
    cluster_bootstrap_token_list, cluster_bootstrap_token_revoke, cluster_bootstrap_token_usage, cluster_clean,
    cluster_mint_join_key, cluster_place_model, cluster_reconcile_models, cluster_set_primary,
    cluster_restart_backends, cluster_import_model, cluster_ship_model, cluster_sync_images, cluster_upgrade_agents, cluster_upgrade_applier, cluster_upgrade_hostd,
};
pub use db::{db_current, db_history, db_stamp, db_status, db_upgrade, db_verify_plane};
pub use doctor::{
    doctor_docker, doctor_exposure, doctor_orphans, doctor_privileges, doctor_secrets,
    doctor_strangers,
};
pub use tailnet_policy::tailnet_policy;
pub use enroll::enroll;
pub mod agent_secret_files;
pub mod env_quote;
pub mod node_fetch;
pub mod node_leaves;
pub mod data_root;
pub use node_fetch::node_fetch;
pub use config::{config_export_effective, config_get, config_launch_check, config_launch_render, config_set, config_show};
pub use graph::{graph_clusters_audit, graph_detail, graph_entity_cleanup, graph_prune_restore, graph_navigate, graph_neighbors, graph_recluster, graph_search, graph_stats};
pub mod ops;
pub use ops::{ops_cancel, ops_list, ops_show, ops_types};
pub use walks::{walks_list, walks_settings, walks_show, walks_stats, walks_view};
pub use health::health;
pub use heartbeat::{
    heartbeat_add, heartbeat_approve, heartbeat_export, heartbeat_history, heartbeat_import, heartbeat_list,
    heartbeat_proposals, heartbeat_reject, heartbeat_review_existing, heartbeat_remove, heartbeat_run, heartbeat_set_schedule, heartbeat_status, heartbeat_toggle,
};
pub use inference::{inference_agent, inference_run};
pub use jobs::{
    jobs_cancel, jobs_drain, jobs_history, jobs_list, jobs_pause, jobs_reprioritize, jobs_resume,
    jobs_run, jobs_scheduler, jobs_status, jobs_submit, jobs_undrain,
};
pub use logs::{logs_containers, logs_errors, logs_query, logs_search, logs_status, logs_tail};
pub use mcp::{mcp_export, mcp_external_setup, mcp_import, mcp_place, mcp_server_add, mcp_server_disable, mcp_server_enable, mcp_server_list, mcp_server_remove, mcp_server_show, mcp_tools, mcp_unplace};
pub use memory::{
    memory_conversations, memory_embed, memory_embed_status, memory_embed_stop, memory_health,
    memory_search, memory_stats, memory_tool_stats,
};
pub use mesh::{
    mesh_clean, mesh_logs, mesh_rebuild, mesh_rebuild_status, mesh_restart, mesh_start,
    mesh_status, mesh_stop,
};
pub use migrate::{migrate_export, migrate_import};
pub use models_fetch::models_fetch;
pub use models::{
    models_cached, models_huggingface, models_info, models_list, models_ollama, models_pull,
    models_recommended, models_search,
};
pub use pki::{pki_fix_modes, pki_init, pki_issue, pki_issue_client, pki_issue_gateway, pki_issue_service, pki_issue_sso_key, pki_revoke_client, pki_rotate, pki_rotate_client, pki_status};
pub use proactive::{proactive_history, proactive_rules, proactive_status};
pub use prompt_skills::{
    prompt_skills_create, prompt_skills_evolve, prompt_skills_info, prompt_skills_list,
};
pub use rag::{
    rag_deduplicate, rag_doc, rag_docs, rag_held, rag_hold, rag_ingest, rag_purge, rag_query, rag_retag, rag_scan,
    rag_status, rag_unhold,
};
pub use security::{
    security_audit_list, security_audit_verify,
    security_org_create, security_org_list, security_posture_apply_profile,
    security_posture_list, security_posture_set, security_service_key_issue,
    security_service_key_list, security_service_key_provision, security_service_key_retire,
    security_service_key_revoke,
    security_service_key_rotate,
    security_service_key_self, security_service_key_self_revoke, security_service_key_self_status,
    security_service_key_set_quota, security_team_create, security_team_delete,
    security_team_link_space, security_team_list, security_team_spaces,
    security_team_unlink_space, security_user_create, security_user_decide,
    security_user_disable, security_user_enable, security_user_erase, security_user_grant_role, security_user_link,
    security_user_links, security_user_list, security_user_list_roles, security_user_proposals,
    security_user_revoke_role, security_user_set_org, security_user_set_password,
    security_admin_password_reset,
    security_user_allowance, security_user_set_scopes, security_user_unlink,
};
pub use secrets::{secrets_audit, secrets_resync, secrets_rotate, secrets_tidy};
pub use secrets_remove::secrets_remove;
pub use secrets_reveal::secrets_reveal;
// ── Fleet secret convergence (WP-FS): the missing push half of a rotation.
pub use cluster_host_telemetry::{cluster_host_telemetry_apply, cluster_host_telemetry_usage};
pub use cluster_vendor::{cluster_vendor_install, cluster_vendor_stage, cluster_vendor_status, cluster_vendor_usage};
pub use cluster_push_secrets::cluster_push_secrets;
pub use cluster_gpu::{cluster_gpu_hold, cluster_gpu_release};
pub use cluster_profile::cluster_profile;
pub use cluster_verify::cluster_verify;
pub use cluster_class::{cluster_class_list, cluster_class_set, cluster_class_unset, cluster_prefer};
pub use cluster_embedding_space::{cluster_embedding_space_list, cluster_embedding_space_set, cluster_embedding_space_unset};
pub use security_local::{
    secrets_absorb_files,
    cluster_teardown_node, pki_issue_node, pki_push_nodes, pki_rotate_all, security_generate_secret, security_scan, security_trust_ca,
    security_untrust_ca, pki_rotate_ca, pki_rotate_signing_key,
};
pub use skills::{skills_info, skills_list, skills_run, skills_scaffold};
pub use test::{test_coverage, test_run};
pub use tools::{tools_export, tools_info, tools_list, tools_select};
pub use bundle::bundle_export;
pub use provision::cluster_provision;
pub use offboard::offboard;
pub use upgrade::upgrade;
pub use usage::{usage, usage_me};

/// `noo tui` — RETIRED 2026-08-16. Native so the answer needs no Python and
/// a broken venv can't turn it into a traceback: the web dashboard
/// (noo-mesh-ui-web, served by the gateway) is the interactive UI; `noo
/// chat` covers the terminal. Module archived at legacy/python-tui-reference/.
pub fn tui_retired(g: &crate::Globals, _args: &[String]) -> Result<i32, crate::Unhandled> {
    crate::output::fail(
        g.json,
        crate::output::ExitCode::Generic,
        "tui_retired",
        "the terminal UI is retired — use the web dashboard or `noo chat`.",
        None,
    );
}
pub use voice::{voice_speak, voice_status, voice_synthesize, voice_transcribe, voice_voices};
pub use recall::{
    recall_archive, recall_lifecycle, recall_prominent, recall_refresh, recall_search,
    recall_stats, recall_status, recall_test, recall_videos,
};
pub use workflow::{workflow_list, workflow_run};
// ── WP-B2: stack mgmt (distinct block to avoid registry-edit collisions).
pub use cluster::cluster_seed;
pub use controller::{controller_demote, controller_promote};
pub use mesh::{mesh_install_watcher, mesh_ollama, mesh_reset, mesh_sandbox, mesh_sync_assets};
pub use models::models_switch;
// ── WP-PL: plugins (distinct block to avoid registry-edit collisions).
pub use plugins::plugins_list;
pub use models::models_refresh;
pub mod addon_cli;

/// Destructive-operation confirmation, agent-first (shared by `stack clean`,
/// `cluster down`, `cluster scale`). Semantics:
///   `--yes/-y`      → proceed, no prompt (the agent path).
///   `--json`        → NEVER prompt: without --yes emit the JSON error
///                     contract on stderr and exit 1.
///   stdin not a TTY → error out instead of blocking on a pipe. Deliberate
///                     improvement over Python's `typer.confirm`, which
///                     hangs waiting for input in agent/pipe contexts.
///   TTY             → Python's exact prompt text (`{action} {target}?`,
///                     `[y/N]` suffix); only "y"/"yes" (case-insensitive)
///                     proceeds, anything else prints "Aborted." and exits 1.
pub(crate) fn confirm_destructive(g: &crate::Globals, yes: bool, action: &str, target: &str) {
    confirm_prompt(g, yes, &format!("{action} {target}?"));
}

/// [`confirm_destructive`] with the whole question supplied, for callers that
/// are handed a sentence they must show verbatim (an add-on's `confirm`).
pub(crate) fn confirm_prompt(g: &crate::Globals, yes: bool, prompt: &str) {
    use std::io::{BufRead as _, Write as _};
    if yes {
        return;
    }
    if g.json {
        crate::output::fail(
            true,
            crate::output::ExitCode::Generic,
            "confirmation_required",
            "confirmation required: pass --yes",
            Some(&format!("refusing to prompt in --json mode; would ask: {prompt}")),
        );
    }
    if unsafe { libc::isatty(0) } != 1 {
        crate::output::fail(
            false,
            crate::output::ExitCode::Generic,
            "confirmation_required",
            &format!(
                "confirmation required: pass --yes (stdin is not a TTY; refusing to block on: {prompt})"
            ),
            Some("agents and pipes must confirm destructive commands explicitly with --yes/-y"),
        );
    }
    // Interactive prompt goes to stderr so stdout stays data-only.
    eprint!("{prompt} [y/N]: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    let ans = line.trim().to_ascii_lowercase();
    if ans != "y" && ans != "yes" {
        eprintln!("Aborted.");
        std::process::exit(crate::output::ExitCode::Generic as i32);
    }
}

/// A step with a live spinner: `ui::Step`. Kept as a named constructor so
/// call sites read `Spinner::start(g, msg)`; finish it with
/// `.done(..)`/`.warned(..)`/`.failed(..)`, or drop it to just stop.
pub(crate) struct Spinner;

impl Spinner {
    pub(crate) fn start(g: &crate::Globals, msg: &str) -> crate::ui::Step {
        let _ = g; // mode is process-global in `ui` now
        crate::ui::Step::start(msg)
    }
}

/// Exit code for a response body that carries a top-level `error` key.
///
/// Several gateway routes answer **HTTP 200** with `{"error": "Redis not
/// connected", "jobs": []}`. In human mode the renderers now say so, but the
/// `--json` branches printed the body and returned 0 — so a script that checks
/// only the exit status scored a dead job store as a successful empty query.
/// Use this in place of a bare `Ok(0)` after printing a JSON body.
///
/// Only the *top level* is inspected: a job record's own `error` field is
/// payload, not a transport failure.
pub(crate) fn json_exit(body: &serde_json::Value) -> i32 {
    match body.get("error").and_then(|e| e.as_str()) {
        Some(s) if !s.is_empty() => crate::output::ExitCode::RemoteError as i32,
        _ => 0,
    }
}

/// Char-boundary-safe truncation (log lines may contain multibyte UTF-8).
/// Render an RFC3339 timestamp as a compact age (`3m`, `2h`, `4d`).
/// A null or absent value is a dash — the gateway not saying is not "never".
pub(crate) fn ago(v: &serde_json::Value) -> String {
    let Some(ts) = v.as_str() else { return crate::ui::dash().to_string() };
    let Ok(then) = time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339)
    else {
        return crate::ui::dash().to_string();
    };
    let secs = (time::OffsetDateTime::now_utc() - then).whole_seconds();
    if secs < 0 {
        return crate::ui::dash().to_string();
    }
    let s = match secs {
        s if s < 90 => format!("{s}s"),
        s if s < 5400 => format!("{}m", s / 60),
        s if s < 172_800 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    };
    crate::ui::muted(&s)
}

pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Terminal size from the kernel (`TIOCGWINSZ` on stdout, then stderr —
/// stderr is usually still the terminal when stdout is piped), `$COLUMNS`
/// / `$LINES` as an explicit override, else 120×40. Non-interactive
/// shells, ssh sessions and WSL rarely export COLUMNS, so asking the tty
/// is what makes the boxed header fit.
pub(crate) fn term_size() -> (usize, usize) {
    // The tty is the truth when it answers: an exported COLUMNS is often
    // stale (set at login, never updated on resize), and a stale wide value
    // wraps every box and rule (operator, 2026-09-03). COLUMNS/LINES are
    // the override only when no tty answers (pipes, CI).
    let (mut cols, mut rows) = (None, None);
    for fd in [1, 2] {
        // SAFETY: ioctl with a zeroed winsize out-param on our own fds;
        // a failure leaves the struct zeroed and we fall through.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
        if rc == 0 && ws.ws_col >= 20 {
            cols = Some(ws.ws_col as usize);
            if ws.ws_row >= 5 {
                rows = Some(ws.ws_row as usize);
            }
            break;
        }
    }
    let env = |k: &str, min: usize| {
        std::env::var(k).ok().and_then(|v| v.parse::<usize>().ok()).filter(|n| *n >= min)
    };
    let cols = cols.or_else(|| env("COLUMNS", 20)).unwrap_or(120);
    let rows = rows.or_else(|| env("LINES", 5)).unwrap_or(40);
    (cols.max(40), rows)
}

/// Render width: see [`term_size`]. Rows are read too now — by
/// `ui::pager_finish`, which decides whether the output needs a pager at all.
/// That comment used to say `less -F` owned the decision; it could not, because
/// `-F` only applies when the pager reaches EOF before it paints.
pub(crate) fn term_width() -> usize {
    term_size().0
}

/// Percent-encode a query-string value (RFC 3986 unreserved set kept).
pub(crate) fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub use entitlement::*;
#[cfg(has_entitlement_signer)]
pub use entitlement_signer::*;
pub use release_sign::*;
pub use addon_lock_cmd::{security_addon_lock_sign, security_addon_lock_verify};
pub use addon_pins::{addons_launch_pins, addons_upgrade, addons_verify};
pub use addons::{addons_disable, addons_enable, addons_list};
pub use backups::{backups_setup, backups_status};
pub use kiosk::*;
pub use kiosk_seat::{kiosk_enroll, kiosk_seat_sync, kiosk_seat_token};
