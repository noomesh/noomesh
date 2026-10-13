// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! noo — Rust front-door for the Noomesh CLI.
//!
//! Dispatch rule: this binary natively handles ONLY the commands in
//! [`NATIVE`] whose arguments it fully understands. An unknown command word
//! then gets one git-style chance as a plugin — an executable `noo-<word>`
//! shim on PATH or in the user plugins dir (see `commands/plugins.rs`) is
//! exec()'d with the remaining argv. Everything else — unknown commands,
//! unknown flags, `--help`, bare `noo` — is exec()'d through to the Python
//! CLI (`noomesh.cli`), which remains the complete reference surface
//! during the piece-by-piece port. Order: builtins → plugins → Python.
//! Porting a command = adding a registry entry + handler; no other
//! coordination needed.
//!
//! Agent contract (applies to every native command):
//!   - `--json` prints the gateway's JSON to stdout, nothing else.
//!   - Errors go to stderr — as JSON (`{"error","code","hint"}`) in json mode.
//!   - Exit codes: 0 ok, 1 generic, 2 usage, 3 gateway unreachable,
//!     4 auth failed, 5 gateway returned an error status.
//!
//! Environment parity with `noomesh/cli_utils.py`: loads the repo `.env`
//! (already-exported vars win) and resolves the gateway URL the same way.
//! Credentials are per-USER, never a shared secret: `auth::resolve` takes
//! `--token` → `$NOO_TOKEN` → the stored credential written by
//! `noo auth login`, and nothing else (`--break-glass` was removed).

// Pre-existing clippy lints in the handler modules (predate the CI gate added
// with the dispatch test harness). Allowed crate-wide so `cargo clippy -D
// warnings` gates NEW code without a churn-heavy reformat of the ported
// command handlers. Tighten/remove as those modules are cleaned up.
//   - print_literal / useless_borrows_in_formatting: stylistic format-arg nits
//   - doc_overindented_list_items / doc_lazy_continuation: rustdoc list spacing
//   - if_same_then_else / unnecessary_lazy_evaluations: handler branch style
//   - too_many_arguments / ptr_arg: pki.rs issuance signatures
// Tolerate lint names that don't exist in every clippy version — some of the
// allows below (e.g. useless_borrows_in_formatting) were renamed/removed in
// newer clippy, and an unknown-lint name is itself an error under -D warnings.
#![allow(unknown_lints)]
#![allow(clippy::print_literal)]
#![allow(clippy::useless_borrows_in_formatting)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::unnecessary_lazy_evaluations)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::ptr_arg)]

mod addon_lock;
mod auth;
mod catalog;
mod child_stdin;
mod commands;
mod credentials;
mod entitlement;
mod entitlement_terms;
mod registry;
mod release_fetch;
mod release_sig;
mod envfile;
#[cfg(test)]
mod hint_lint;
mod host_access;
mod http;
pub(crate) mod onboard;
mod operator_cert;
mod output;
mod passthrough;
mod pki;
mod role;
mod shell_completion;
mod tailnet_serve;
mod ui;
mod usage;
mod vendor;

use output::{fail, ExitCode};

/// A handler returns `Err(Unhandled)` when it sees an argument it doesn't
/// understand — the dispatcher then exec()s Python with the ORIGINAL argv,
/// so partially-ported flag surfaces degrade gracefully instead of erroring.
#[derive(Debug)]
pub struct Unhandled;

type Handler = fn(&Globals, &[String]) -> Result<i32, Unhandled>;

/// Native command registry: leading positional words → handler.
/// The handler receives the tokens after the matched words.
const NATIVE: &[(&[&str], Handler)] = &[
    (&["health"], commands::health),
    (&["whoami"], role::whoami),
    (&["node", "fetch"], commands::node_fetch),
    (&["cluster", "status"], commands::cluster_status),
    (&["jobs", "list"], commands::jobs_list),
    (&["inference", "run"], commands::inference_run),
    (&["db", "status"], commands::db_status),
    (&["doctor", "docker"], commands::doctor_docker),
    (&["doctor", "privileges"], commands::doctor_privileges),
    (&["doctor", "orphans"], commands::doctor_orphans),
    (&["doctor", "secrets"], commands::doctor_secrets),
    (&["doctor", "exposure"], commands::doctor_exposure),
    (&["doctor", "strangers"], commands::doctor_strangers),
    // Same function as `noo backups status`, on purpose. An off-site copy
    // that was never configured is a host-plane fact, and `doctor` is where
    // an operator goes looking for those — but a second implementation of
    // the same question is how the two answers drift apart. One function,
    // two doors.
    (&["doctor", "backups"], commands::backups_status),
    (&["enroll"], commands::enroll),
    (&["cluster", "invite"], commands::cluster_invite),
    (&["db", "verify-plane"], commands::db_verify_plane),
    (&["db", "current"], commands::db_current),
    (&["db", "history"], commands::db_history),
    (&["db", "upgrade"], commands::db_upgrade),
    (&["db", "stamp"], commands::db_stamp),
    (&["config", "get"], commands::config_get),
    (&["config", "set"], commands::config_set),
    // Hidden internal command — see `HIDDEN_NATIVE` below and
    // `commands::launch_render`. Only the launcher scripts call this.
    (&["config", "launch-render"], commands::config_launch_render),
    // Hidden internal command — `commands::bind_sources`; the launchers
    // (scripts/lib-bind-sources.sh) call it before every `compose up`.
    (&["config", "launch-check"], commands::config_launch_check),
    (&["logs", "errors"], commands::logs_errors),
    (&["logs", "tail"], commands::logs_tail),
    (&["logs", "search"], commands::logs_search),
    (&["heartbeat", "status"], commands::heartbeat_status),
    (&["heartbeat", "list"], commands::heartbeat_list),
    (&["heartbeat", "run"], commands::heartbeat_run),
    (&["heartbeat", "history"], commands::heartbeat_history),
    (&["heartbeat", "export"], commands::heartbeat_export),
    (&["heartbeat", "toggle"], commands::heartbeat_toggle),
    (&["heartbeat", "set-schedule"], commands::heartbeat_set_schedule),
    (&["heartbeat", "proposals"], commands::heartbeat_proposals),
    (&["heartbeat", "review-existing"], commands::heartbeat_review_existing),
    (&["heartbeat", "approve"], commands::heartbeat_approve),
    (&["heartbeat", "reject"], commands::heartbeat_reject),
    (&["approval", "list"], commands::approval_list),
    (&["approval", "pending"], commands::approval_list), // alias (MCP naming)
    (&["approval", "stats"], commands::approval_stats),
    (&["approval", "status"], commands::approval_status),
    (&["memory", "search"], commands::memory_search),
    (&["memory", "stats"], commands::memory_stats),
    (&["memory", "health"], commands::memory_health),
    (&["memory", "tool-stats"], commands::memory_tool_stats),
    // Embed-worker control (Redis flag flip on the Rust gateway);
    // `--watch/-w` polls progress natively (memory.rs watch_embed_progress).
    (&["memory", "embed"], commands::memory_embed),
    (&["memory", "embed-status"], commands::memory_embed_status),
    (&["memory", "embed-stop"], commands::memory_embed_stop),
    (&["rag", "query"], commands::rag_query),
    (&["rag", "status"], commands::rag_status),
    (&["rag", "docs"], commands::rag_docs),
    (&["rag", "doc"], commands::rag_doc),
    (&["rag", "ingest"], commands::rag_ingest),
    (&["rag", "scan"], commands::rag_scan),
    (&["rag", "deduplicate"], commands::rag_deduplicate),
    (&["rag", "retag"], commands::rag_retag),
    (&["rag", "hold"], commands::rag_hold),
    (&["rag", "unhold"], commands::rag_unhold),
    (&["rag", "held"], commands::rag_held),
    (&["rag", "purge"], commands::rag_purge),
    (&["graph", "stats"], commands::graph_stats),
    (&["graph", "search"], commands::graph_search),
    (&["graph", "detail"], commands::graph_detail),
    (&["graph", "neighbors"], commands::graph_neighbors),
    (&["graph", "navigate"], commands::graph_navigate),
    (&["graph", "recluster"], commands::graph_recluster),
    (&["graph", "entity-cleanup"], commands::graph_entity_cleanup),
    (&["graph", "prune", "restore"], commands::graph_prune_restore),
    (&["graph", "clusters", "audit"], commands::graph_clusters_audit),
    // Your own saved graph threads. The bare `walks` entry is
    // LAST: dispatch takes the first prefix match, so it must follow its subcommands.
    // Asynchronous operations (gateway ops.rs). The bare `ops` entry is LAST
    // of its group: dispatch takes the first prefix match.
    (&["ops", "show"], commands::ops_show),
    (&["ops", "cancel"], commands::ops_cancel),
    (&["ops", "types"], commands::ops_types),
    (&["ops", "list"], commands::ops_list),
    (&["ops"], commands::ops_list),
    (&["walks", "show"], commands::walks_show),
    (&["walks", "settings"], commands::walks_settings),
    (&["walks", "stats"], commands::walks_stats),
    (&["walks", "view"], commands::walks_view),
    (&["walks"], commands::walks_list),
    (&["autonomy", "status"], commands::autonomy_status),
    (&["autonomy", "locations"], commands::autonomy_status), // Python alias: same view
    (&["autonomy", "audit"], commands::autonomy_audit),
    (&["autonomy", "decisions"], commands::autonomy_decisions),
    (&["autonomy", "enable"], commands::autonomy_enable),
    (&["autonomy", "disable"], commands::autonomy_disable),
    (&["proactive", "status"], commands::proactive_status),
    (&["proactive", "rules"], commands::proactive_rules),
    (&["proactive", "history"], commands::proactive_history),
    (&["channels", "status"], commands::channels_status),
    (&["channels", "export"], commands::channels_export),
    (&["channels", "import"], commands::channels_import),
    (&["agents", "list"], commands::agents_list),
    (&["agents", "peer", "list"], commands::agents_peer_list),
    (&["agents", "peer", "card"], commands::agents_peer_card),
    (&["workflow", "list"], commands::workflow_list),
    (&["workflow", "run"], commands::workflow_run),
    (&["recall", "status"], commands::recall_status),
    (&["recall", "videos"], commands::recall_videos),
    (&["recall", "search"], commands::recall_search),
    (&["recall", "prominent"], commands::recall_prominent),
    (&["recall", "stats"], commands::recall_stats),
    (&["recall", "lifecycle-stats"], commands::recall_stats), // alias (endpoint naming)
    (&["prompt-skills", "list"], commands::prompt_skills_list),
    (&["prompt-skills", "info"], commands::prompt_skills_info),
    (&["prompt-skills", "get"], commands::prompt_skills_info), // alias (agent naming)
    (&["models", "cached"], commands::models_cached),
    // Streaming NDJSON/SSE progress from /api/terminal/ollama/pull.
    (&["models", "pull"], commands::models_pull),
    // Download a GGUF from Hugging Face into the controller store
    // (resume + LFS sha256 verify; commands/models_fetch.rs).
    (&["models", "fetch"], commands::models_fetch),
    (&["browser", "status"], commands::browser_status),
    (&["browser", "open"], commands::browser_open),
    (&["browser", "stop"], commands::browser_stop),
    (&["tools", "list"], commands::tools_list),
    (&["tools", "select"], commands::tools_select),
    (&["tools", "info"], commands::tools_info),
    // `mesh` group: SELF-MANAGEMENT surface — spawns docker/scripts, no
    // gateway/auth, so it works when the venv or gateway is down.
    (&["stack", "status"], commands::mesh_status),
    (&["stack", "logs"], commands::mesh_logs),
    (&["stack", "restart"], commands::mesh_restart),
    (&["stack", "start"], commands::mesh_start),
    (&["stack", "stop"], commands::mesh_stop),
    (&["stack", "rebuild"], commands::mesh_rebuild),
    (&["stack", "rebuild-status"], commands::mesh_rebuild_status),
    // Destructive commands with the agent-first confirm contract:
    // --yes skips, --json requires --yes, non-TTY stdin errors (no hang).
    (&["stack", "clean"], commands::mesh_clean),
    // `noo migrate` moves a CONTROLLER between devices — not schema
    // migrations (those are `noo db upgrade`).
    // `noo controller promote|demote` — warm-standby failover via the
    // stable role name (see commands/controller.rs).
    (&["controller", "promote"], commands::controller_promote),
    (&["controller", "demote"], commands::controller_demote),
    (&["migrate", "export"], commands::migrate_export),
    (&["migrate", "import"], commands::migrate_import),
    (&["cluster", "down"], commands::cluster_down),
    (&["cluster", "scale"], commands::cluster_scale),
    (&["cluster", "desired"], commands::cluster_desired),
    (&["cluster", "proposals"], commands::cluster_proposals),
    (&["cluster", "verify"], commands::cluster_verify),
    (&["cluster", "show"], commands::cluster_show),
    (&["cluster", "forget"], commands::cluster_forget),
    (&["cluster", "place"], commands::cluster_place),
    (&["cluster", "unplace"], commands::cluster_unplace),
    (&["cluster", "fit"], commands::cluster_fit),
    (&["cluster", "class", "list"], commands::cluster_class_list),
    (&["cluster", "class", "set"], commands::cluster_class_set),
    (&["cluster", "class", "unset"], commands::cluster_class_unset),
    // `cluster exec`/`logs` spawn ssh with inherited stdio (fixes the
    // Python versions' swallowed stdout) and propagate the remote rc.
    (&["cluster", "logs"], commands::cluster_logs),
    (&["cluster", "restart-agent"], commands::cluster_restart_agent),
    (&["cluster", "maintenance"], commands::cluster_maintenance),
    (&["cluster", "up"], commands::cluster_up),
    // Batch 3: HTTP/local control + SSH provisioning-adjacent commands.
    (&["cluster", "init-secret"], commands::cluster_init_secret),
    (&["cluster", "assign"], commands::cluster_assign),
    (&["cluster", "set-config"], commands::cluster_set_config),
    (&["cluster", "clear-cooldowns"], commands::cluster_clear_cooldowns),
    (&["cluster", "add-companion"], commands::cluster_add_companion),
    (&["cluster", "add-monitor"], commands::cluster_add_monitor),
    // Destructive SSH cleanup (agent-first confirm contract).
    (&["cluster", "clean-node"], commands::cluster_clean_node),
    (&["cluster", "teardown-node"], commands::cluster_teardown_node),
    // ── Native node provisioning ── the controller half of node
    // birth without ansible/python/Go/repo: certs + env + image-extracted
    // binary + unit as ONE signed bundle via noo-gate.
    (&["cluster", "provision"], commands::cluster_provision),
    // ── Controller teardown / freshness audit (mirror of onboard) ──
    (&["offboard"], commands::offboard),
    // ── Standalone bundle producer ── writes this binary's
    // embedded deploy slice as a versioned tar.gz (+ .sha256) that
    // `noo onboard --standalone --bundle <ref>` consumes.
    (&["bundle", "export"], commands::bundle_export),
    // Long transfers / fleet SSH — spawn ssh/scp with inherited stdio.
    (&["cluster", "exec"], commands::cluster_exec),
    (&["cluster", "reconnect"], commands::cluster_reconnect),
    (&["cluster", "sync-models"], commands::cluster_sync_models),
    (&["cluster", "sync-model-files"], commands::cluster_sync_model_files),
    // Provisioning surface (standalone-controller port): placement planners
    // (native HTTP+local), Tailscale-API commands (mint-join-key/set-primary),
    // and the ssh/scp/docker orchestrators (sync-images/upgrade-agents/
    // ship-model/clean). `clean` is destructive → confirm.
    (&["cluster", "auto-place"], commands::cluster_auto_place),
    (&["cluster", "place-model"], commands::cluster_place_model),
    (&["cluster", "reconcile-models"], commands::cluster_reconcile_models),
    (&["cluster", "mint-join-key"], commands::cluster_mint_join_key),
    // Bootstrap-token enrollment: thin HTTP over the gateway's
    // /api/security/bootstrap-tokens surface.
    (&["cluster", "bootstrap-token", "create"], commands::cluster_bootstrap_token_create),
    (&["cluster", "bootstrap-token", "list"], commands::cluster_bootstrap_token_list),
    (&["cluster", "bootstrap-token", "revoke"], commands::cluster_bootstrap_token_revoke),
    // Group stub AFTER the subactions: resolution is FIRST match in table
    // order, so the real entries win when their word is present and this
    // catches every near-miss — which previously fell through to the
    // Python passthrough and died in irrelevant "set NOO_PY_CLI" advice
    // (finding #89, live: `bootstrap-token --node host5` sans `create`).
    (&["cluster", "bootstrap-token"], commands::cluster_bootstrap_token_usage),
    (&["cluster", "set-primary"], commands::cluster_set_primary),
    (&["cluster", "sync-images"], commands::cluster_sync_images),
    // Stage images on the controller's artifact rail (nodes pull only from there).
    (&["cluster", "stage-images"], commands::cluster_stage_images),
    (&["cluster", "upgrade-agents"], commands::cluster_upgrade_agents),
    (&["cluster", "upgrade-hostd"], commands::cluster_upgrade_hostd),
    (&["cluster", "upgrade-applier"], commands::cluster_upgrade_applier),
    (&["cluster", "restart-backends"], commands::cluster_restart_backends),
    // One operator command to switch off tailscaled's log upload on existing
    // nodes over the pull rail; the group stub after it catches near-misses.
    (&["cluster", "host-telemetry", "apply"], commands::cluster_host_telemetry_apply),
    (&["cluster", "host-telemetry"], commands::cluster_host_telemetry_usage),
    // Move ONE node's agent out of its container. The node is
    // a required positional rather than a --host-process flag on
    // upgrade-agents, so "the whole fleet" is not expressible.
    // Fleet secret convergence: probe each node's .env by salted digest, write
    // only a positively-verified disagreement, re-verify. Destructive → confirm.
    (&["cluster", "push-secrets"], commands::cluster_push_secrets),
    // Per-principal NATS credentials. `nats-users
    // render` mints every principal's password and writes the server-side
    // block from the GATEWAY REGISTRY (never an inventory file); `nats-creds
    // rotate` mints AND delivers one node's credential over the rail and
    // exits non-zero if the node does not confirm the apply.
    (&["cluster", "nats-users", "render"], commands::cluster_nats_users_render),
    (&["cluster", "nats-creds", "rotate"], commands::cluster_nats_creds_rotate),
    (&["cluster", "ship-model"], commands::cluster_ship_model),
    (&["cluster", "import-model"], commands::cluster_import_model),
    (&["cluster", "clean"], commands::cluster_clean),
    // `security pki` group: fully LOCAL certificate operations (no gateway).
    // Word match is exact, so `rotate` and `rotate-all` (registered in the
    // WP-B1 block below) are independent entries; unported `security …`
    // commands fall through untouched.
    (&["security", "pki", "status"], commands::pki_status),
    (&["security", "pki", "init"], commands::pki_init),
    (&["security", "pki", "issue"], commands::pki_issue),
    (&["security", "pki", "issue-service"], commands::pki_issue_service),
    (&["security", "pki", "issue-gateway"], commands::pki_issue_gateway),
    (&["security", "pki", "issue-sso-key"], commands::pki_issue_sso_key),
    (&["security", "pki", "rotate"], commands::pki_rotate),
    (&["security", "pki", "fix-modes"], commands::pki_fix_modes),
    // The operator's own client certificate — the credential
    // posture writes carry instead of the shared secret.
    (&["security", "pki", "issue-client"], commands::pki_issue_client),
    (&["security", "pki", "rotate-client"], commands::pki_rotate_client),
    (&["security", "pki", "revoke-client"], commands::pki_revoke_client),
    // ── Batch: skills / test / debug (added in a distinct block to avoid a
    // merge collision with concurrent registry edits; reconcile order freely).
    // `skills list/info` = local manifest scan; `skills run` is fully native:
    // `--gateway/-g` posts to the gateway, the default drives the node-agent's
    // container executor directly (skills.rs skills_run_local).
    (&["skills", "list"], commands::skills_list),
    (&["skills", "info"], commands::skills_info),
    (&["skills", "run"], commands::skills_run),
    // `skills scaffold`: purely local file generation — the
    // sanctioned replacement for the deleted in-process tools/custom/ loader.
    (&["skills", "scaffold"], commands::skills_scaffold),
    // `test run/coverage` spawn pytest (subprocess, inherited stdio, exit-code
    // propagated). gen-stub/accept/status were retired 2026-09-03.
    (&["test", "run"], commands::test_run),
    (&["test", "coverage"], commands::test_coverage),
    // NOTE: `debug query` was RETIRED 2026-09-03 (not ported): the
    // memory-trace it wanted is trellion's, and trellion has its own CLI.
    // The gateway's /api/v1/debug/query (an admin SQL passthrough, never a
    // trace) was removed 2026-09-27.
    // `onboard`: the setup wizard, native for zero-Python bootstrap —
    // including the browser frontend (`--web [--port N]`, embedded server +
    // SSE, WP-W2) and the ratatui `--tui` frontend (WP-W1). The ONLY wizard:
    // the Python reference was archived (legacy/python-onboard) and unknown
    // flags are an error, never a fallthrough.
    (&["onboard"], onboard::onboard),
    // ── WP-A1: jobs — queue + scheduler control, thin HTTP to the gateway
    // (jobs_cli.py parity; `jobs list` was ported earlier, above). Distinct
    // block at the end of the table to avoid merge collisions with parallel
    // work packages; reconcile order freely.
    (&["jobs", "run"], commands::jobs_run),
    (&["jobs", "status"], commands::jobs_status),
    (&["jobs", "submit"], commands::jobs_submit),
    (&["jobs", "history"], commands::jobs_history),
    // Destructive (agent-first confirm contract: --yes/-y skips the prompt).
    (&["jobs", "cancel"], commands::jobs_cancel),
    (&["jobs", "reprioritize"], commands::jobs_reprioritize),
    (&["jobs", "scheduler"], commands::jobs_scheduler),
    (&["jobs", "pause"], commands::jobs_pause),
    (&["jobs", "resume"], commands::jobs_resume),
    (&["jobs", "drain"], commands::jobs_drain),
    (&["jobs", "undrain"], commands::jobs_undrain),
    // ── WP-A2: models — HuggingFace-backed catalog commands (list/search/
    // info/recommended/ollama/huggingface). `models switch` went native in
    // WP-B2 and `models refresh` in WP-R (see their blocks below).
    (&["models", "list"], commands::models_list),
    (&["models", "search"], commands::models_search),
    (&["models", "info"], commands::models_info),
    (&["models", "recommended"], commands::models_recommended),
    (&["models", "ollama"], commands::models_ollama),
    (&["models", "huggingface"], commands::models_huggingface),
    // ── WP-A6: config ───────────────────────────────────────────────────────
    // `show` is fully LOCAL (noomesh.yaml search-path read, no gateway —
    // a missing explicit file is a local error, never gateway_unreachable);
    // `export-effective` is a best-effort composite (tolerant fetches embed
    // {"error": …} like the Python CLI and always exit 0).
    (&["config", "show"], commands::config_show),
    (&["config", "export-effective"], commands::config_export_effective),
    // ── WP-A5: agents/channels/inference ── long-request POSTs (multi-agent
    // collaborate, peer dispatch, channel test send, agentic loop) and
    // prompt-skill authoring. (`tools export` was deferred here because
    // /tools/list strips the nats_subject routing metadata + extended
    // tool groups; it went native in WP-TE once the gateway grew
    // GET /api/tools/registry/raw — see the WP-TE block at the table end.)
    (&["agents", "collaborate"], commands::agents_collaborate),
    (&["agents", "send"], commands::agents_send),
    (&["agents", "inbox"], commands::agents_inbox),
    (&["agents", "thread"], commands::agents_thread),
    (&["agents", "presence"], commands::agents_presence),
    (&["agents", "messages"], commands::agents_messages),
    (&["tasks", "create"], commands::tasks_create),
    (&["tasks", "list"], commands::tasks_list),
    (&["tasks", "show"], commands::tasks_show),
    (&["tasks", "stop"], commands::tasks_stop),
    (&["agents", "peer", "dispatch"], commands::agents_peer_dispatch),
    (&["channels", "test"], commands::channels_test),
    (&["inference", "agent"], commands::inference_agent),
    (&["prompt-skills", "create"], commands::prompt_skills_create),
    (&["prompt-skills", "evolve"], commands::prompt_skills_evolve),
    // ── WP-A4: observability — logs (containers/LogQL/Loki status), memory
    // conversation listing, recall archive/lifecycle/refresh triggers +
    // local test stub, heartbeat task add/remove. `debug query` stays
    // Python (see the NOTE above). `heartbeat remove` is destructive →
    // agent-first confirm contract (--yes skips, --json requires --yes,
    // non-TTY stdin errors).
    (&["logs", "containers"], commands::logs_containers),
    (&["logs", "query"], commands::logs_query),
    (&["logs", "status"], commands::logs_status),
    (&["memory", "conversations"], commands::memory_conversations),
    (&["recall", "archive"], commands::recall_archive),
    (&["recall", "lifecycle"], commands::recall_lifecycle),
    (&["recall", "refresh"], commands::recall_refresh),
    (&["recall", "test"], commands::recall_test),
    (&["heartbeat", "add"], commands::heartbeat_add),
    (&["heartbeat", "import"], commands::heartbeat_import),
    (&["stack", "sync-assets"], commands::mesh_sync_assets),
    (&["heartbeat", "remove"], commands::heartbeat_remove),
    // ── WP-C1: chat — native REPL/one-shot over the gateway's SSE streaming
    // path (POST /api/inference/stream, served natively by gateway-rust).
    // The Python local-agent fallback surface (--no-use-cluster, --config,
    // --base-url, --tool-mode) falls through to Python; gateway down → exit 3
    // with a pointer to `noo stack start` / the Python fallback.
    (&["chat"], commands::chat),
    // ── WP-A3: security (HTTP surface) — users / teams / orgs / posture /
    // service-keys, all thin gateway calls (security_cli.py `_api`/`_team_api`).
    // `security pki *` stays in its block above; generate-secret / scan /
    // trust-ca / untrust-ca / pki rotate-all are Phase-2 and fall through.
    (&["security", "user", "list"], commands::security_user_list),
    (&["security", "user", "create"], commands::security_user_create),
    (&["security", "user", "grant-role"], commands::security_user_grant_role),
    (&["security", "user", "revoke-role"], commands::security_user_revoke_role),
    (&["security", "user", "list-roles"], commands::security_user_list_roles),
    (&["security", "user", "link"], commands::security_user_link),
    (&["security", "user", "unlink"], commands::security_user_unlink),
    (&["security", "user", "links"], commands::security_user_links),
    (&["security", "user", "set-password"], commands::security_user_set_password),
    (&["security", "admin-password", "reset"], commands::security_admin_password_reset),
    // Auth scopes, not the KB roles that `grant-role` handles — admin-only.
    (&["security", "user", "set-scopes"], commands::security_user_set_scopes),
    (&["security", "user", "set-org"], commands::security_user_set_org),
    (&["security", "user", "disable"], commands::security_user_disable),
    (&["security", "user", "enable"], commands::security_user_enable),
    // `user erase` keeps Python's dry-run-unless-`--yes` contract;
    // `team delete` uses the agent-first confirm (stack clean style).
    (&["security", "user", "erase"], commands::security_user_erase),
    (&["security", "user", "proposals"], commands::security_user_proposals),
    (&["security", "user", "decide"], commands::security_user_decide),
    (&["security", "team", "list"], commands::security_team_list),
    (&["security", "team", "create"], commands::security_team_create),
    (&["security", "team", "delete"], commands::security_team_delete),
    (&["security", "team", "link-space"], commands::security_team_link_space),
    (&["security", "team", "unlink-space"], commands::security_team_unlink_space),
    (&["security", "team", "spaces"], commands::security_team_spaces),
    (&["security", "org", "list"], commands::security_org_list),
    (&["security", "org", "create"], commands::security_org_create),
    (&["security", "audit", "verify"], commands::security_audit_verify),
    (&["security", "posture", "list"], commands::security_posture_list),
    (&["security", "tailnet", "policy"], commands::tailnet_policy),
    (&["security", "posture", "set"], commands::security_posture_set),
    (&["security", "posture", "apply-profile"], commands::security_posture_apply_profile),
    (&["security", "service-key", "issue"], commands::security_service_key_issue),
    (&["security", "service-key", "list"], commands::security_service_key_list),
    (&["security", "service-key", "revoke"], commands::security_service_key_revoke),
    (&["security", "service-key", "retire"], commands::security_service_key_retire),
    (&["security", "service-key", "provision"], commands::security_service_key_provision),
    (&["security", "service-key", "rotate"], commands::security_service_key_rotate),
    (&["security", "service-key", "set-quota"], commands::security_service_key_set_quota),
    // Self-service: any account mints its OWN mcp key, no operator in the
    // loop. Longest-prefix dispatch puts these ahead of the CONSUMER-taking
    // `issue`/`revoke` above, so `self` can never be read as a consumer name.
    (&["security", "service-key", "self"], commands::security_service_key_self),
    (&["security", "service-key", "self-status"], commands::security_service_key_self_status),
    (&["security", "service-key", "self-revoke"], commands::security_service_key_self_revoke),
    // ── end WP-A3 block ──
    // ── WP-B1: security local — generate-secret (token_urlsafe/Fernet),
    // scan (env/config posture checks), trust-ca/untrust-ca (OS trust store
    // with native elevation), and pki rotate-all (the former Python holdout:
    // rotate expiring leafs + docker restart + health probe + auto-revert,
    // composed from pki.rs/mesh-style spawning/health probing). Exact word
    // match keeps `rotate-all` independent of the `rotate` entry above.
    (&["security", "generate-secret"], commands::security_generate_secret),
    // ── `security secrets` — audit + rotate the app secret store (LOCAL,
    // no gateway). `audit` is read-only and safe BY CONSTRUCTION: it reports
    // key names, presence, set/BLANK/missing, length and sha256[:8], and has
    // no code path that can emit a value. It exists so nobody ever again
    // answers "do these two stores agree?" by decrypting to a file and
    // diffing it — which on 2026-08-03 put the entire store in a terminal
    // transcript. `rotate` is destructive → agent-first confirm contract.
    (&["systems", "status"], commands::systems::systems_status),
    (&["systems", "enable"], commands::systems::systems_enable),
    (&["systems", "disable"], commands::systems::systems_disable),
    (&["security", "entitlement", "keygen"], commands::entitlement_keygen),
    (&["security", "entitlement", "issue"], commands::entitlement_issue),
    (&["security", "entitlement", "install"], commands::entitlement_install),
    (&["security", "entitlement", "show"], commands::entitlement_show),
    (&["security", "entitlement", "verify"], commands::entitlement_verify),
    (&["security", "release-sign"], commands::release_sign),
    (&["security", "release-verify"], commands::release_verify),
    (&["security", "addon-lock", "sign"], commands::security_addon_lock_sign),
    (&["security", "addon-lock", "verify"], commands::security_addon_lock_verify),
    (&["security", "secrets", "audit"], commands::secrets_audit),
    (&["security", "secrets", "tidy"], commands::secrets_tidy),
    (&["security", "secrets", "resync"], commands::secrets_resync),
    (&["security", "secrets", "rotate"], commands::secrets_rotate),
    (&["security", "secrets", "remove"], commands::secrets_remove),
    (&["security", "secrets", "reveal"], commands::secrets_reveal),
    (&["security", "scan"], commands::security_scan),
    (&["security", "pki", "rotate-all"], commands::pki_rotate_all),
    (&["security", "pki", "rotate-ca"], commands::pki_rotate_ca),
    (&["security", "pki", "rotate-signing-key"], commands::pki_rotate_signing_key),
    (&["security", "secrets", "absorb-files"], commands::secrets_absorb_files),
    (&["security", "pki", "issue-node"], commands::pki_issue_node),
    (&["security", "pki", "push-nodes"], commands::pki_push_nodes),
    (&["security", "trust-ca"], commands::security_trust_ca),
    // Destructive (agent-first confirm contract: --yes skips, --json
    // requires --yes, non-TTY stdin errors instead of hanging).
    (&["security", "untrust-ca"], commands::security_untrust_ca),
    // ── WP-B2: stack mgmt (distinct block — reconcile order freely).
    // `stack install-watcher` = retired stub (noo-hostd runs host commands);
    // `stack reset` spawns scripts/noomesh-reset.sh (destructive → agent-
    // first confirm contract); `stack ollama` = docker-exec passthrough with
    // inherited stdio; `models switch` rewrites noomesh.yaml/.env + compose-
    // recreates the backend; `cluster seed` applies/exports desired state.
    (&["stack", "install-watcher"], commands::mesh_install_watcher),
    (&["stack", "reset"], commands::mesh_reset),
    // Throwaway DinD full stack for rehearsals/testing.
    (&["stack", "sandbox"], commands::mesh_sandbox),
    (&["stack", "ollama"], commands::mesh_ollama),
    (&["models", "switch"], commands::models_switch),
    (&["cluster", "seed"], commands::cluster_seed),
    // ── WP-4a: approval decide — thin HTTP to POST /api/approval/{id}/decide
    // (the gateway write path that replaced the CLI's direct-SQL UPDATE;
    // cluster-HMAC bearer accepted there under host-operator trust).
    (&["approval", "approve"], commands::approval_approve),
    (&["approval", "deny"], commands::approval_deny),
// ── WP-V: voice — thin HTTP to the gateway voice routes (whisper/TTS
    // proxies in gateway-rust routes/communication.rs), replacing the Python
    // CLI's in-process faster-whisper/piper surface. `speak` synthesizes via
    // the gateway then plays through the first system player on PATH
    // (paplay/aplay/ffplay/afplay) — no audio libraries bundled.
    // `transcribe --device` has no gateway field → Unhandled → Python.
    (&["voice", "transcribe"], commands::voice_transcribe),
    (&["voice", "synthesize"], commands::voice_synthesize),
    (&["voice", "speak"], commands::voice_speak),
    (&["voice", "status"], commands::voice_status),
    (&["voice", "voices"], commands::voice_voices),
    // ── WP-PL: plugins — git-style `noo-<name>` executable shims. `plugins
    // list` enumerates them natively (LOCAL PATH + user-dir scan, no gateway);
    // dispatch of `noo <name> …` to a shim is the Resolution::Plugin fallback
    // below (builtins → plugins → Python), not a registry entry. Python-
    // package plugins (~/.noo/plugins, imported in-process) remain the Python
    // CLI's surface — see src/commands/plugins.rs.
    (&["plugins", "list"], commands::plugins_list),
    // ── WP-TE: tools export ── thin HTTP to GET /api/tools/registry/raw
    // (routes/ui.rs), the raw-registry endpoint added for exactly this port
    // (plan §Phase 4b): full core_tools incl. tags/speed/nats_subject +
    // extended_tool_groups. Was DEV_ONLY (WP-A5) while only the stripped
    // /tools/list existed.
    (&["tools", "export"], commands::tools_export),
    // ── WP-R: models refresh — native catalog rebuild: HuggingFace fetch
    // with the 24h TTL bypassed, overwriting the shared
    // ~/.config/mesh/model_cache.json (Python-compatible shape both ways);
    // `--llm` POSTs the coordinator eval to /api/inference (best-effort,
    // result stored in the cache file, exactly like Python).
    (&["models", "refresh"], commands::models_refresh),
    // ── WP-M: mcp — the gateway's operator door owns the external MCP connections
    // (worker_pool registers them at startup), so `mcp tools` asks it via a
    // minimal streamable-http JSON-RPC exchange (initialize → tools/list)
    // instead of Python's in-process MCPClientManager; presents NOO_MCP_KEY
    // (a per-admin `mcp:operator` key). `external-setup` is fully local: token
    // mint + config snippets, `--save` appends to the repo .env.
    (&["mcp", "tools"], commands::mcp_tools),
    (&["mcp", "external-setup"], commands::mcp_external_setup),
    // The registry of EXTERNAL MCP servers — the
    // record and its placements. Discovery (B) and the bridge (C) follow.
    (&["mcp", "server", "add"], commands::mcp_server_add),
    (&["mcp", "server", "list"], commands::mcp_server_list),
    (&["mcp", "server", "show"], commands::mcp_server_show),
    (&["mcp", "server", "enable"], commands::mcp_server_enable),
    (&["mcp", "server", "disable"], commands::mcp_server_disable),
    (&["mcp", "server", "remove"], commands::mcp_server_remove),
    (&["mcp", "place"], commands::mcp_place),
    (&["mcp", "unplace"], commands::mcp_unplace),
    (&["mcp", "import"], commands::mcp_import),
    (&["mcp", "export"], commands::mcp_export),
    // ── WP-L: pro loop ── meta-cognitive self-improvement engine, thin HTTP
    // to the gateway's pro routes. The handler module is pro-only (compiled
    // in only when present — see commands/mod.rs); in OSS builds these
    // handlers stub to Unhandled and the argv falls through to Python. The
    // engine itself is runtime-gated too: a gateway without the evolve add-on
    // renders a friendly "pro loop engine not enabled" (exit 5).
    // ── CLI per-user auth ── obtain,
    // inspect and drop a per-person credential instead of signing with the
    // shared cluster HMAC. `login` hits the gateway's existing
    // POST /auth/token; nothing gateway-side changed.
    (&["auth", "login"], commands::auth_login),
    (&["auth", "status"], commands::auth_status),
    (&["auth", "logout"], commands::auth_logout),
    // ── Token-usage summary ── thin GET /api/usage/summary.
    (&["usage"], commands::usage),
    // ── Self-update ── download+verify+swap the running binary; native
    // so it works on a box with NO repo (the standalone controller update path).
    (&["upgrade"], commands::upgrade),
    (&["backups", "setup"], commands::backups_setup),
    (&["backups", "status"], commands::backups_status),
    (&["addons", "list"], commands::addons_list),
    (&["addons", "enable"], commands::addons_enable),
    (&["addons", "disable"], commands::addons_disable),
    (&["kiosk", "invite"], commands::kiosk_invite),
    (&["kiosk", "labels"], commands::kiosk_labels),
    (&["kiosk", "reload"], commands::kiosk_reload),
    (&["kiosk", "serve"], commands::kiosk_serve),
    (&["kiosk", "setup"], commands::kiosk_setup),
    (&["kiosk", "status"], commands::kiosk_status),
    (&["kiosk", "teardown"], commands::kiosk_teardown),
    // ── tui (RETIRED 2026-08-16) ── native so the answer needs no Python:
    // the web dashboard is the interactive UI; `noo chat` covers the
    // terminal. Module archived at legacy/python-tui-reference/.
    (&["tui"], commands::tui_retired),
];

/// Full command paths that ARE in [`NATIVE`] (so they dispatch, have a
/// [`usage::USAGE`] row, and are unit-tested) but are not something an
/// operator would ever type by hand — they exist for another program to
/// call. Filtered out of `noo <group> --help`'s subcommand listing and of
/// tab-completion, the same way `completion_candidates`'s `HIDE` keeps
/// whole test/plugin-seam groups off the top-level list.
///
/// `config launch-render` is the launcher's internal reader of
/// `noomesh.yaml` (`scripts/lib-config.sh`, `lib-addons.sh`,
/// `noomesh-start.sh`'s override regen) — see `commands::launch_render`.
/// `config launch-check` is the launchers' pre-`up` bind-source check
/// (`scripts/lib-bind-sources.sh`) — see `commands::bind_sources`.
///
/// Also hidden: vendor/CI-only verbs a customer never runs (`security
/// entitlement keygen|issue`, `security release-sign`, `security addon-lock
/// sign`), and `security pki
/// rotate`, a pure alias of `security pki issue` (same certificate call).
/// All still dispatch and answer `--help`.
const HIDDEN_NATIVE: &[&[&str]] = &[
    &["config", "launch-render"],
    &["config", "launch-check"],
    // Pure aliases and internal/retired verbs: still dispatched, not in help.
    &["approval", "pending"],
    &["autonomy", "locations"],
    &["ops"],
    &["kiosk", "serve"],
    &["tools", "select"],
    // Aliases and retired verbs: they still work, but are not offered.
    &["recall", "lifecycle-stats"],
    &["prompt-skills", "get"],
    &["recall", "test"],
    &["mcp", "external-setup"],
    // Vendor/CI-only and a pure alias (security slice).
    &["security", "entitlement", "keygen"],
    &["security", "entitlement", "issue"],
    &["security", "release-sign"],
    &["security", "addon-lock", "sign"],
    &["security", "pki", "rotate"],
];

/// Commands that still dispatch but are not in customer help, completion or
/// the generated docs, and so have NO `usage::USAGE` row:
///   * retired stubs that only print the replacement (`tui`, `stack
///     install-watcher`, `db stamp`);
///   * a pure alias (`doctor backups` is `backups status`);
///   * the dev-checkout pytest runners (`test run`, `test coverage`), which
///     need a python venv and the repo's tests/ tree and fail on a shipped
///     install.
const HIDDEN_NO_USAGE: &[&[&str]] = &[
    &["tui"],
    // Plumbing and retired `cluster` verbs: dispatch only.
    &["node", "fetch"],
    &["cluster", "clean-node"],
    &["cluster", "exec"],
    &["cluster", "reconnect"],
    &["cluster", "sync-models"],
    &["stack", "install-watcher"],
    &["db", "stamp"],
    &["doctor", "backups"],
    &["test", "run"],
    &["test", "coverage"],
];

fn is_hidden_native(entry: &[&str]) -> bool {
    HIDDEN_NATIVE.contains(&entry) || HIDDEN_NO_USAGE.contains(&entry)
}

/// Emit a shell completion script derived from the NATIVE registry.
/// The table is the single source of truth for both dispatch and completion,
/// so this can never drift as commands are added.
///
///   noo completions bash   # complete -F
///   noo completions zsh    # compdef
///   noo completions fish   # complete
///
/// Install (bash):  noo completions bash | sudo tee /etc/bash_completion.d/pai
/// Completion candidates for the words typed so far (excluding the
/// current, partial word): position 1 = the command groups, position 2 =
/// the group's subcommands, later = live values (task ids, nodes …) via
/// shell_completion::candidates. The installed shell function is a thin
/// shim that asks this for every position, so an upgraded binary changes
/// what <Tab> offers with no shell reload (operator, 2026-09-02).
fn completion_candidates(g: &Globals, words: &[String]) -> Vec<String> {
    const HIDE: &[&str] = &["frob", "definitely-not-a-command", "test"];
    match words.len() {
        0 => {
            let mut tops: Vec<String> = Vec::new();
            for (w, _) in NATIVE {
                if is_hidden_native(w) {
                    continue;
                }
                if let Some(t) = w.first() {
                    if !t.starts_with('-') && !HIDE.contains(t) && !tops.iter().any(|x| x == t) {
                        tops.push((*t).to_string());
                    }
                }
            }
            tops
        }
        1 => {
            let mut subs: Vec<String> = Vec::new();
            for (w, _) in NATIVE {
                if is_hidden_native(w) {
                    continue;
                }
                if w.first().map(|t| *t == words[0]).unwrap_or(false) {
                    if let Some(sub) = w.get(1) {
                        if !subs.iter().any(|x| x == sub) {
                            subs.push((*sub).to_string());
                        }
                    }
                }
            }
            subs.sort_unstable();
            subs
        }
        _ => {
            // Deeper verbs first. 83 commands are three words deep
            // (`security service-key provision`) and this walked only two:
            // <Tab> after `service-key` offered nothing, and after
            // `provision` had no names to offer — which is how a hand-typed
            // `rotate worker` minted a consumer called "worker" beside
            // `svc:worker` (operator, 2026-09-24).
            let mut subs: Vec<String> = Vec::new();
            for (w, _) in NATIVE {
                if is_hidden_native(w) {
                    continue;
                }
                if w.len() > words.len() && w.iter().zip(words.iter()).all(|(a, b)| *a == b) {
                    let next = w[words.len()];
                    if !next.starts_with('-') && !HIDE.contains(&next) && !subs.iter().any(|x| x == next) {
                        subs.push(next.to_string());
                    }
                }
            }
            if !subs.is_empty() {
                subs.sort_unstable();
                return subs;
            }
            // The command is the longest NATIVE prefix of what was typed;
            // everything after it is arguments. The verb handed to the
            // candidate resolver is the whole path below the group
            // ("service-key provision"), so three-word verbs can name a source.
            let cmd_len = NATIVE
                .iter()
                .filter(|(w, _)| w.len() <= words.len() && w.iter().zip(words.iter()).all(|(a, b)| *a == b))
                .map(|(w, _)| w.len())
                .max()
                .unwrap_or(2);
            let verb = words[1..cmd_len].join(" ");
            let live = shell_completion::candidates(g, &words[0], &verb);
            if !live.is_empty() {
                return live;
            }
            // Nothing live to offer. Ask for filenames only if this position
            // actually names one; otherwise offer nothing, so a leaf command
            // does not turn <Tab> into a listing of the operator's $HOME.
            let (cmd, typed) = words.split_at(cmd_len);
            if shell_completion::wants_path(cmd, typed) {
                return vec![shell_completion::FILES.to_string()];
            }
            Vec::new()
        }
    }
}

fn print_completions(shell: &str) -> i32 {
    // group -> sorted unique subcommands. Skip the deliberate test/hidden
    // entries so they never surface in a user's tab-complete.
    const HIDE: &[&str] = &["frob", "definitely-not-a-command", "test"];
    let mut groups: Vec<(&str, Vec<&str>)> = Vec::new();
    for (words, _) in NATIVE {
        if is_hidden_native(words) {
            continue;
        }
        let Some(top) = words.first() else { continue };
        if top.starts_with('-') || HIDE.contains(top) {
            continue;
        }
        let entry = match groups.iter_mut().find(|(g, _)| g == top) {
            Some(e) => e,
            None => {
                groups.push((top, Vec::new()));
                groups.last_mut().unwrap()
            }
        };
        if let Some(sub) = words.get(1) {
            if !entry.1.contains(sub) {
                entry.1.push(sub);
            }
        }
    }
    for (_, subs) in groups.iter_mut() {
        subs.sort_unstable();
    }
    let tops: Vec<&str> = groups.iter().map(|(g, _)| *g).collect();

    match shell {
        "bash" => {
            // A SHIM: it never needs regenerating. Every position asks the
            // binary (static for groups/subs, live for arguments, 3s cap),
            // so `noo upgrade` changes what <Tab> offers in shells that
            // are already open — no `exec bash`.
            println!("# noo bash completion — generated by `noo completions bash` (shim: asks the binary)");
            println!("_noo_complete() {{");
            println!("    local cur=\"${{COMP_WORDS[COMP_CWORD]}}\" cands");
            println!("    cands=$(timeout 3 noo completions candidates \"${{COMP_WORDS[@]:1:COMP_CWORD-1}}\" 2>/dev/null)");
            println!("    if [ \"$cands\" = \"__files__\" ]; then compopt -o default 2>/dev/null; COMPREPLY=(); return; fi");
            println!("    if [ -n \"$cands\" ]; then compopt +o default 2>/dev/null; COMPREPLY=($(compgen -W \"$cands\" -- \"$cur\")); return; fi");
            // No candidates and no path wanted: offer nothing. `+o default`
            // suppresses bash's filename fallback, which used to dump the
            // whole home directory at every leaf command (host8, 2026-09-05).
            println!("    compopt +o default 2>/dev/null; COMPREPLY=()");
            println!("}}");
            println!("complete -F _noo_complete noo pai");
        }
        "zsh" => {
            println!("#compdef noo");
            println!("# noo zsh completion — generated by `noo completions zsh` (shim: asks the binary)");
            println!("_noo() {{");
            println!("    local -a cands; cands=(${{(f)\"$(timeout 3 noo completions candidates ${{words[2,CURRENT-1]}} 2>/dev/null)\"}})");
            println!("    if [[ \"$cands\" == \"__files__\" ]]; then _files; return; fi");
            println!("    if (( ${{#cands}} )); then compadd -- $cands; return; fi");
            println!("}}");
            println!("compdef _noo noo pai");
        }
        "fish" => {
            for g in &tops {
                println!("complete -c noo -n '__fish_use_subcommand' -a '{}'", g);
            }
            for (g, subs) in &groups {
                for s in subs {
                    println!("complete -c noo -n '__fish_seen_subcommand_from {}' -a '{}'", g, s);
                }
            }
        }
        _ => {
            eprintln!("noo completions: unknown shell '{shell}' (want: bash | zsh | fish)");
            return 64;
        }
    }
    0
}

/// Bare `noo --help`: the native banner, always. Every group Python's Typer
/// tree listed is native now except `debug`, so the Rust side is the
/// reference surface and Python's help (stale taglines, `noo-py` in the
/// usage line) no longer represents the binary the user is holding.
/// Sections are editorial; a test pins every registry group to exactly one.
const GROUP_SECTIONS: &[(&str, &[&str])] = &[
    ("Setup & host", &["whoami", "onboard", "enroll", "offboard", "upgrade", "doctor", "health", "migrate", "controller", "bundle", "systems", "addons", "kiosk", "backups"]),
    ("Fleet", &["cluster", "models", "tools", "inference", "jobs", "autonomy", "skills", "browser"]),
    ("Stack & data", &["stack", "db", "logs", "config", "heartbeat", "usage", "plugins"]),
    ("Memory & knowledge", &["memory", "rag", "recall", "graph", "walks", "ops", "prompt-skills"]),
    ("Agents & channels", &["chat", "agents", "tasks", "workflow", "voice", "channels", "proactive", "approval", "mcp"]),
    ("Security", &["security", "auth"]),
];

/// Top-level words the Python CLI still owns outright. Anything else that
/// is not a registry group or a plugin is an unknown command and gets a
/// native answer with suggestions instead of Python's "No such command".
/// Empty since `debug` was retired 2026-09-03; kept so the next Python-only
/// group (if one ever appears) has a declared home.
const PYTHON_ONLY_GROUPS: &[&str] = &[];

fn print_native_help(g: &Globals) {
    // The wordmark carries the tagline + version itself; the one-line
    // title is the plain-mode (and --quiet/--json-less) equivalent.
    let mark = ui::wordmark(env!("CARGO_PKG_VERSION"));
    if mark.is_empty() {
        println!(
            "{} {} — local-first AI agent mesh",
            ui::emph("noo"),
            env!("CARGO_PKG_VERSION")
        );
    } else {
        print!("{mark}");
    }
    // First-run tip (§5): a box with no install gets pointed at the two
    // ways in, before the group list.
    let role = role::detect();
    if role.controller.is_none() && role.node.is_none() && !ui::quiet() {
        ui::guide(&[
            ("noo onboard", "set this machine up as a controller (the setup wizard)"),
            ("noo enroll <controller-url>", "join an existing fleet as a worker node"),
        ]);
    }
    println!("{}", ui::section("usage"));
    println!("  noo <group> <command> [args]     noo <group> --help     noo <group> <command> --help");
    let groups: Vec<&str> = {
        let mut g: Vec<&str> = Vec::new();
        for (words, _) in NATIVE {
            if is_hidden_native(words) {
                continue;
            }
            if let Some(w) = words.first() {
                if !g.contains(w) {
                    g.push(w);
                }
            }
        }
        g
    };
    let width = groups.iter().map(|g| g.len()).max().unwrap_or(8);
    let mut placed: Vec<&str> = Vec::new();
    for (title, members) in GROUP_SECTIONS {
        println!("{}", ui::section(title));
        for g in *members {
            if groups.contains(g) {
                placed.push(g);
                println!("  {}  {}", ui::cmd(&format!("{g:<width$}")), group_desc(g));
            }
        }
    }
    let rest: Vec<&str> = groups.iter().copied().filter(|g| !placed.contains(g)).collect();
    if !rest.is_empty() {
        println!("{}", ui::section("other"));
        for g in rest {
            println!("  {}  {}", ui::cmd(&format!("{g:<width$}")), group_desc(g));
        }
    }
    commands::addon_cli::print_help_section(g, width);
    println!("{}", ui::section("globals"));
    print!(
        "{}",
        ui::kv(&[
            ("--json", format!("raw gateway JSON on stdout  {}", ui::muted("scripts and agents"))),
            ("--quiet, -q", format!("captured values only  {}", ui::muted("ids, secrets, paths"))),
            ("--color MODE", format!("auto | always | never  {}", ui::muted("persist: noo config set cli '{\"color\":\"never\"}'"))),
            ("--watch [S]", format!("redraw a status command every S seconds  {}", ui::muted("stack status, cluster status, jobs list"))),
            ("-G, --gateway URL", "target another gateway".to_string()),
            ("--instance NAME", "target a named instance".to_string()),
            ("--timeout S", "per-request timeout".to_string()),
            ("--token JWT", "explicit per-user credential".to_string()),
            ("-v, --verbose", "show requests and subprocess commands".to_string()),
        ])
    );
    println!();
    if PYTHON_ONLY_GROUPS.is_empty() {
        println!("{}", ui::muted("`noo <group> --help` lists each group's commands · `noo --version` · `noo completions <shell>`"));
    } else {
        println!(
            "{}",
            ui::muted(&format!(
                "Python-only (dev venv): {}. `noo <group> --help` lists each group's commands.",
                PYTHON_ONLY_GROUPS.join(", ")
            ))
        );
    }
}

fn group_desc(group: &str) -> &'static str {
    GROUP_DESC
        .iter()
        .find(|(g, _)| *g == group)
        .map(|(_, d)| *d)
        .unwrap_or("")
}

/// Suggestions for an unknown top-level word: native commands that contain
/// the word (`status` → `cluster status`, `stack status`, …), then groups the
/// word prefixes or is a near-miss of. Pure, so it is testable.
fn suggest(word: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // Groups first: `noo stack` is a better answer to a bare `mesh`-ish word
    // than six of its subcommands, and a group exact-match must never be
    // truncated away by them.
    let mut groups: Vec<&str> = Vec::new();
    for (entry, _) in NATIVE {
        if let Some(g) = entry.first() {
            if !groups.contains(g) {
                groups.push(g);
            }
        }
    }
    for g in &groups {
        if g.starts_with(word) || word.starts_with(g) || edit_distance(g, word) <= 2 {
            let s = format!("noo {g}");
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    // Then commands that contain the word anywhere (`status` → `cluster
    // status`, `stack status`, …).
    for (entry, _) in NATIVE {
        if entry.len() > 1 && entry[1..].contains(&word) {
            let s = format!("noo {}", entry.join(" "));
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out.truncate(6);
    out
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// One-line description per top-level command group, rendered by the native
/// `--help` tree. Mirrors the sub-app table in CLAUDE.md; a group absent
/// here still renders, just without a tagline — never a reason to fail.
const GROUP_DESC: &[(&str, &str)] = &[
    ("cluster", "Node management, provisioning (bootstrap-token + pull rail), teardown"),
    ("models", "Model catalog, search, pull, recommended"),
    ("tools", "Cluster tool registry"),
    ("autonomy", "Autonomy engine monitoring & control"),
    ("jobs", "Job queue & scheduler management"),
    ("skills", "Containerized skill management"),
    ("browser", "Browser automation"),
    ("chat", "Interactive chat with the cluster"),
    ("agents", "Multi-agent collaboration"),
    ("tasks", "Objectives the agent loops on until done"),
    ("workflow", "Workflow automation"),
    ("voice", "STT + TTS"),
    ("channels", "Channel adapter management"),
    ("proactive", "Proactive agent loop"),
    ("inference", "Run prompts on the GPU cluster"),
    ("graph", "Knowledge graph exploration"),
    ("walks", "Your saved graph threads: recall them, and control saving"),
    ("ops", "Asynchronous operations: long runs started as an op, polled for their result"),
    ("approval", "Exec approval queue"),
    ("prompt-skills", "Prompt skill templates"),
    ("stack", "The Docker stack on THIS host: start/stop/restart/clean/status (the fleet is `cluster`)"),
    ("controller", "Warm-standby failover: promote/demote via the stable role name"),
    ("migrate", "Move this controller to another device (export/import; NOT schema migrations)"),
    ("memory", "Memory & embedding management"),
    ("rag", "PageIndex RAG commands"),
    ("recall", "Episodic recall (System 1 memory)"),
    ("security", "Users, secrets, PKI, scanning, CA trust"),
    ("config", "Runtime configuration"),
    ("heartbeat", "Cron scheduler for automated tasks"),
    ("mcp", "MCP server tools"),
    ("db", "Schema migrations: mesh via the gateway's native runner, memory via alembic in trellion"),
    ("doctor", "Host-plane health checks with guided recovery"),
    ("whoami", "What this box is: controller, node, both, or client-only"),
    ("node", "This node's pull-rail poller (macOS: run by the net.noomesh.fetch LaunchDaemon)"),
    ("enroll", "Join this machine to a noomesh fleet as a worker"),
    ("logs", "Log aggregation"),
    ("plugins", "Plugin management"),
    ("onboard", "Setup wizard"),
    ("auth", "Per-user CLI credentials"),
    ("usage", "Token-usage summary"),
    ("bundle", "Signed bundle inspection"),
    ("health", "Gateway health probe"),
    ("offboard", "Leave the fleet: stop the agent, remove enrollment state (confirms)"),
    ("systems", "Enable/disable optional systems (mints their secrets into sops)"),
    ("upgrade", "Self-update the CLI; --stack/--nodes/--controller roll the rest"),
    ("addons", "Which add-ons this install runs — the `addons:` map, without opening the file"),
    ("kiosk", "The unattended display's host seat: cage + Chromium showing /kiosk.html"),
    ("backups", "Where backups go — and whether anyone has decided"),
];

/// Native help for a command-word prefix, rendered entirely from the
/// registry plus the per-command usage table (`usage.rs`) — no Python
/// required and no hand-maintained command list to drift (a test pins the
/// two tables 1:1). `words` is what the user typed before `--help`; it
/// matches the registry either as a strict prefix of entries (a group →
/// list children with their argument syntax) or with an entry as ITS
/// prefix (an exact command → full usage for that command, then its
/// sub-entries if any).
fn print_native_help_for(words: &[String]) {
    let as_strs: Vec<&str> = words.iter().map(String::as_str).collect();
    let mut exact: Option<&'static [&'static str]> = None;
    let mut children: Vec<&'static [&'static str]> = Vec::new();
    for (entry, _) in NATIVE {
        let group_child = entry.len() > as_strs.len()
            && entry.iter().zip(&as_strs).all(|(a, b)| a == b);
        let exact_or_parent = entry.len() <= as_strs.len()
            && entry.iter().zip(&as_strs).all(|(a, b)| a == b);
        if group_child {
            // Hidden internal commands (config launch-render, …) don't
            // clutter `noo <group> --help`'s subcommand list — they exist
            // for another program to call, not an operator to discover.
            if !is_hidden_native(entry) {
                children.push(entry);
            }
        } else if exact_or_parent && exact.is_none_or(|e| entry.len() > e.len()) {
            exact = Some(entry);
        }
    }
    let head = as_strs.first().copied().unwrap_or("");
    let desc = GROUP_DESC
        .iter()
        .find(|(g, _)| *g == head)
        .map(|(_, d)| *d)
        .unwrap_or("");

    if let Some(entry) = exact {
        let (syntax, about) = usage::lookup(entry).unwrap_or(("", ""));
        let joined = entry.join(" ");
        println!("{}", ui::header_as_is(&format!("noo {joined}"), if about.is_empty() { None } else { Some(about) }));
        println!("{}", ui::section("usage"));
        if syntax.is_empty() {
            println!("  {}", ui::cmd(&format!("noo {joined}")));
        } else {
            println!("  {} {syntax}", ui::cmd(&format!("noo {joined}")));
        }
        if !children.is_empty() {
            println!("{}", ui::section("subcommands"));
            print_usage_rows(&children);
        }
    } else {
        println!("{}", ui::header_as_is(&format!("noo {}", as_strs.join(" ")), if desc.is_empty() { None } else { Some(desc) }));
        println!("{}", ui::section("commands"));
        print_usage_rows(&children);
    }
    println!();
    println!(
        "{}",
        ui::muted("Globals: --json  --quiet  --color <mode>  --watch [s]  -v  -G/--gateway <url>  --timeout <s>  --token <jwt>  --instance <name>")
    );
}

/// Two-column rows: `noo <words> <syntax>` left, description right, wrapped
/// so a long syntax never squeezes the description off the terminal.
fn print_usage_rows(entries: &[&'static [&'static str]]) {
    let rows: Vec<(String, &str)> = entries
        .iter()
        .map(|e| {
            let (syntax, about) = usage::lookup(e).unwrap_or(("", ""));
            let left = if syntax.is_empty() {
                format!("noo {}", e.join(" "))
            } else {
                format!("noo {} {syntax}", e.join(" "))
            };
            (left, about)
        })
        .collect();
    let width = rows
        .iter()
        .map(|(l, _)| l.chars().count())
        .filter(|w| *w <= 48)
        .max()
        .unwrap_or(0);
    for (left, about) in rows {
        if about.is_empty() {
            println!("  {}", ui::cmd(&left));
        } else if left.chars().count() <= width {
            println!("  {}  {about}", ui::cmd(&format!("{left:<width$}")));
        } else {
            println!("  {}", ui::cmd(&left));
            println!("  {:<width$}  {about}", "");
        }
    }
}

/// Why `--break-glass` is refused (it was removed, not renamed).
pub const BREAK_GLASS_REMOVED: &str = "the global break-glass flag was removed: the CLI never signs \
with the controller's shared secret, and the gateway refuses one a noo CLI signs. Log in as \
yourself; posture writes take your operator certificate";

/// The recovery the refusal points at — every command an ordinary path.
pub const BREAK_GLASS_RECOVERY: &str = "noo auth login   # lost the password? on the controller: \
noo security admin-password reset; lost your operator certificate? noo security pki issue-client <you> --force";

/// Global options shared by every native command. `Clone` so the onboarding
/// TUI can hand an owned copy to its wizard worker thread.
#[derive(Debug, PartialEq, Clone)]
pub struct Globals {
    pub json: bool,
    pub verbose: bool,
    pub gateway_override: Option<String>,
    /// Set only when the user passed --timeout; commands apply their own
    /// defaults otherwise (10s for reads, 120s for inference).
    pub timeout_secs: Option<u64>,
    /// `--token <jwt>` — explicit per-user credential, highest precedence in
    /// `auth::resolve`.
    pub token: Option<String>,
    /// `--quiet`/`-q` — captured values only (CLI_STYLE_GUIDE §7).
    pub quiet: bool,
}

/// The outcome of parsing an argv into a dispatch decision — the pure part of
/// `main()`, factored out so it can be unit-tested without touching the
/// process, the gateway, or Python. `main()` maps each variant to an action.
#[derive(Debug, PartialEq)]
pub enum Resolution {
    /// A native command matched. `prefix` is the exact registry entry (the
    /// leading command words); `rest` is the full post-global-flag token
    /// stream — the handler receives `rest[prefix.len()..]`.
    Native {
        prefix: &'static [&'static str],
        rest: Vec<String>,
    },
    /// `--version` / `-V` — report our own version, no Python needed.
    Version,
    /// `completions <shell>` — emit a shell completion script. Native
    /// so it works with no Python present, and generated from the registry.
    Completions { shell: String, args: Vec<String> },
    /// Bare `noo` or `--help`/`-h` — `main()` prints the native banner when no
    /// Python is present, otherwise falls through to Python's rich help.
    Help,
    /// `--help`/`-h` after command words that match the native registry —
    /// rendered natively, ALWAYS (never Python): native commands must
    /// describe themselves on an install with no venv, and must not turn a
    /// broken venv into a traceback. `words` is everything typed before the
    /// help flag.
    HelpFor { words: Vec<String> },
    /// No native entry matched, but an executable `noo-<name>` shim exists
    /// (PATH or the user plugins dir) — exec it with `args` (the ORIGINAL
    /// argv tokens after the command word, so a plugin sees its own flags
    /// verbatim; noo's global flags BEFORE the word are consumed by us).
    /// Order is git-style: builtins → plugins → Python passthrough. A shim
    /// can never shadow a known command word (native first words and the
    /// PY_ONLY/DEV_ONLY-gated groups are reserved).
    Plugin { name: String, args: Vec<String> },
    /// A first word nothing built in owns and no plugin claims. An enabled
    /// add-on may bring a command group of that name: `main()` asks
    /// `commands::addon_cli`, and when no add-on has the group the word is an
    /// unknown command, exactly as `Passthrough` would have treated it.
    /// `rest` is the post-global-flag token stream.
    Addon { rest: Vec<String> },
    /// Nothing we serve natively — exec the Python CLI with the original argv.
    Passthrough,
}

/// Command words a plugin shim may never claim: every native group's first
/// word, the Python-gated groups (PY_ONLY/DEV_ONLY first words — they carry
/// their own standalone messages), and `py` (the Python CLI shim itself).
/// This keeps the plugin fallback strictly ADDITIVE: it can only serve words
/// the CLI would otherwise hand to Python as unknown.
pub(crate) fn is_reserved_command_word(word: &str) -> bool {
    NATIVE.iter().any(|(words, _)| words.first() == Some(&word))
        || passthrough::is_gated_first_word(word)
        || word == "py"
}

/// Parse `argv` (the args AFTER the program name) into the global options and a
/// dispatch [`Resolution`]. This replicates `main()`'s decision sequence
/// EXACTLY and has no side effects, so tests can assert routing directly:
///   1. consume the global flags we own (`--json`, `-v`/`--verbose`,
///      `--gateway`/`-G <url>`, `--timeout <secs>`) wherever they appear;
///   2. `--version`/`-V` as the first non-global token → [`Resolution::Version`];
///   3. empty argv or a leading `--help`/`-h` → [`Resolution::Help`];
///   4. FIRST registry entry whose words prefix the remaining tokens →
///      [`Resolution::Native`] (first-match, not longest-match);
///   5. a non-reserved first word with a `noo-<word>` shim on the search
///      path → [`Resolution::Plugin`] (git order: builtins → plugins →
///      Python);
///   6. a non-reserved first word with no shim → [`Resolution::Addon`]
///      (an enabled add-on's command group, or an unknown command);
///   7. otherwise [`Resolution::Passthrough`].
///
/// `resolve` uses the real filesystem for step 5; [`resolve_with`] takes the
/// shim-existence predicate as a parameter so the routing stays a pure,
/// unit-testable function.
pub fn resolve(argv: &[String]) -> (Globals, Resolution) {
    resolve_with(argv, |name| commands::plugins::find_plugin(name).is_some())
}

/// See [`resolve`]; `plugin_exists` abstracts the `noo-<name>` shim lookup.
pub fn resolve_with(
    argv: &[String],
    plugin_exists: impl Fn(&str) -> bool,
) -> (Globals, Resolution) {
    // Pass 1: consume the global flags we own (they may appear anywhere);
    // everything else — command words, command flags, values — lands in
    // `rest` in order. Unknown tokens are NOT an error here: if they sit
    // before the command words the registry match fails (→ Python), and
    // after the command words the handler decides.
    let mut globals = Globals {
        json: false,
        verbose: false,
        gateway_override: None,
        timeout_secs: None,
        token: None,
        quiet: false,
    };
    let mut rest: Vec<String> = Vec::new();
    let mut iter = argv.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--json" => globals.json = true,
            "-v" | "--verbose" => globals.verbose = true,
            "--gateway" | "-G" => globals.gateway_override = iter.next().cloned(),
            "--timeout" => globals.timeout_secs = iter.next().and_then(|v| v.parse().ok()),
            "--token" => globals.token = iter.next().cloned(),
            // Output styling (CLI_STYLE_GUIDE.md §3). Recorded as process
            // state like --instance: `ui` resolves the mode once, and every
            // print site asks it. An unknown value is a usage error, not a
            // guess.
            // `--quiet`: only captured values on stdout (guide §2/§7).
            "--quiet" | "-q" => globals.quiet = true,
            "--color" => match iter.next().and_then(|v| ui::Mode::parse(v)) {
                Some(m) => ui::set_mode(m),
                None => output::fail(false, output::ExitCode::Usage, "usage",
                    "--color takes auto, always or never", None),
            },
            t if t.starts_with("--color=") => match ui::Mode::parse(&t["--color=".len()..]) {
                Some(m) => ui::set_mode(m),
                None => output::fail(false, output::ExitCode::Usage, "usage",
                    "--color takes auto, always or never", None),
            },
            // Cross-instance targeting. Setting the env var (not a
            // Globals field) makes ONE resolution path serve everything —
            // envfile::instance(), the credential dir, container names,
            // the port-offset default URL, and Python passthrough alike.
            "--instance" => {
                if let Some(v) = iter.next() {
                    std::env::set_var("NOO_INSTANCE", v);
                }
            }
            // Removed by design: there is no break-glass path, recovery uses the same
            // way end users do. The CLI never signs with a
            // shared secret, and the gateway refuses one a `noo` CLI signs.
            // Refused by name, so a script that still passes it learns why
            // instead of sending an unauthenticated request.
            "--break-glass" => output::fail(false, output::ExitCode::Usage, "removed_flag",
                BREAK_GLASS_REMOVED, Some(BREAK_GLASS_RECOVERY)),
            _ => rest.push(tok.clone()),
        }
    }


    // `--version` is native — a shipped standalone binary must report its own
    // version with no Python present.
    if matches!(rest.first().map(String::as_str), Some("--version") | Some("-V")) {
        return (globals, Resolution::Version);
    }

    // Bare `noo` / `noo --help` — `main()` decides between the native banner
    // (no Python) and Python's rich help. No native command word is ever
    // `--help`/`-h`, so skipping the registry match here is behaviour-neutral.
    let wants_help = argv.is_empty()
        || matches!(rest.first().map(String::as_str), Some("--help") | Some("-h"));
    if wants_help {
        return (globals, Resolution::Help);
    }

    // `--help`/`-h` after command words: if what precedes it touches the
    // native registry (as a group prefix or an exact command), help is served
    // natively — a standalone binary must describe its own commands, and a
    // broken venv must not turn `noo security pki issue --help` into a
    // Python traceback (2026-08-16). Prefixes the registry doesn't know keep
    // falling through to Python's rich Typer help.
    if let Some(pos) = rest.iter().position(|t| t == "--help" || t == "-h") {
        let words = &rest[..pos];
        let known = !words.is_empty()
            && NATIVE.iter().any(|(entry, _)| {
                entry
                    .iter()
                    .zip(words.iter())
                    .take_while(|(a, b)| **a == b.as_str())
                    .count()
                    == entry.len().min(words.len())
            });
        if known {
            return (globals, Resolution::HelpFor { words: words.to_vec() });
        }
    }

    if rest.first().map(String::as_str) == Some("completions") {
        let shell = rest.get(1).cloned().unwrap_or_default();
        let args: Vec<String> = rest.iter().skip(2).cloned().collect();
        return (globals, Resolution::Completions { shell, args });
    }

    let matched = NATIVE.iter().find(|(words, _)| {
        rest.len() >= words.len() && words.iter().zip(&rest).all(|(a, b)| a == b)
    });

    if let Some((words, _handler)) = matched {
        return (globals, Resolution::Native { prefix: words, rest });
    }

    // Plugin fallback (git-style, AFTER builtins): a first word that is not a
    // flag and not a reserved command word, with a matching `noo-<word>` shim.
    // The plugin's args come from the ORIGINAL argv (everything after the
    // word), so flags the user put after the plugin name — even ones that
    // collide with our globals like `--json` — reach the plugin verbatim.
    if let Some(word) = rest.first() {
        if !word.starts_with('-') && !is_reserved_command_word(word) {
            if plugin_exists(word) {
                let pos = argv
                    .iter()
                    .position(|t| t == word)
                    .expect("word was drawn from argv");
                return (
                    globals,
                    Resolution::Plugin { name: word.clone(), args: argv[pos + 1..].to_vec() },
                );
            }
            // Not a builtin, not a plugin: an enabled add-on may bring a
            // command group of that name (commands/addon_cli.rs). `main()`
            // looks; when none does, it is the unknown command it always was.
            return (globals, Resolution::Addon { rest });
        }
    }

    (globals, Resolution::Passthrough)
}

/// Look up the handler for a matched native `prefix`. The registry-integrity
/// test guarantees prefixes are unique, so this is unambiguous.
fn handler_for(prefix: &[&str]) -> Handler {
    NATIVE
        .iter()
        .find(|(words, _)| *words == prefix)
        .map(|(_, h)| *h)
        .expect("resolve() only returns prefixes drawn from NATIVE")
}

fn main() {
    // Restore default SIGPIPE so `noo … | head` terminates quietly instead
    // of panicking on EPIPE — agents pipe CLI output constantly. Rust's
    // runtime ignores SIGPIPE by default, turning closed pipes into
    // println! panics.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let argv: Vec<String> = std::env::args().skip(1).collect();

    // The whole dispatch decision is a pure function (see `resolve`); `main`
    // just carries out the resulting action.
    let (globals, resolution) = resolve(&argv);
    // Output-mode side effects live HERE, not in resolve(): resolve is the
    // pure, unit-tested part, and flipping process-global ui state from a
    // test's `--json` argv silenced other tests in the same process.
    if globals.json {
        // --json wins over --quiet: narration off, styling off, but stdout
        // stays ours for the JSON value (no fd redirect).
        ui::set_silent(true);
    } else if globals.quiet {
        ui::set_quiet(true);
    }

    // An add-on's command group: the controller's enabled add-ons describe
    // their own commands (commands/addon_cli.rs). Nothing offering the group
    // leaves it the unknown command it was, handled below.
    let addon_words: Option<Vec<String>> = match &resolution {
        Resolution::Addon { rest } => Some(rest.clone()),
        _ => None,
    };
    if let Resolution::Addon { rest } = &resolution {
        envfile::ensure_repo_env();
        if let Some(code) = commands::addon_cli::run(&globals, rest) {
            ui::pager_finish();
            std::process::exit(code);
        }
    }

    match resolution {
        // `--version` is native — a shipped standalone binary must report its
        // own version with no Python present.
        Resolution::Completions { shell, args } => {
            if shell == "candidates" {
                // `noo completions candidates [words…]` — the shell shim
                // passes the words typed so far; always exits 0.
                for c in completion_candidates(&globals, &args) {
                    println!("{c}");
                }
                std::process::exit(0);
            }
            std::process::exit(print_completions(&shell));
        }
        Resolution::Version => {
            println!("noo (noomesh CLI, alias: pai) {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        // Bare `noo` / `noo --help` with no Python available: print a native
        // banner listing the command groups this binary serves standalone,
        // instead of failing. When Python IS present, fall through to its rich
        // help (which also lists the passthrough commands).
        Resolution::Help => {
            print_native_help(&globals);
            std::process::exit(0);
        }
        Resolution::HelpFor { words } => {
            print_native_help_for(&words);
            std::process::exit(0);
        }
        Resolution::Native { prefix, rest } => {
            if globals.verbose {
                eprintln!(
                    "noo-cli(rust) v{}: native `{}`",
                    env!("CARGO_PKG_VERSION"),
                    prefix.join(" ")
                );
            }
            envfile::ensure_repo_env();
            // Role gate: a controller-only verb on a node-only box says where
            // it runs instead of stumbling through missing secrets (role.rs).
            role::gate(&globals, &rest);
            match handler_for(prefix)(&globals, &rest[prefix.len()..]) {
                Ok(code) => {
                    ui::pager_finish();
                    std::process::exit(code)
                }
                Err(Unhandled) => {
                    // A native command that did not understand its
                    // arguments is a USAGE error, full stop. It used to
                    // fall through to the Python passthrough, which (with
                    // PY_ONLY/DEV_ONLY empty) could only add a misleading
                    // "no Python noo found" complaint after the usage line
                    // (operator, 2026-09-03: `noo cluster place-model
                    // host8 vllm …`). Print the usage, point at --help,
                    // exit 2.
                    let joined = prefix.join(" ");
                    let (syntax, about) = usage::lookup(prefix).unwrap_or(("", ""));
                    let usage_line = if syntax.is_empty() { format!("noo {joined}") } else { format!("noo {joined} {syntax}") };
                    if globals.json {
                        eprintln!(
                            "{}",
                            serde_json::json!({"error": format!("noo {joined} did not understand these arguments"), "code": "usage", "hint": usage_line})
                        );
                    } else {
                        ui::failed(&format!("noo {joined} did not understand these arguments"), None);
                        eprintln!("{}", ui::note(&format!("usage: {usage_line}")));
                        if !about.is_empty() {
                            eprintln!("{}", ui::note(about));
                        }
                        eprintln!("{}", ui::hint(&format!("noo {joined} --help")));
                    }
                    std::process::exit(output::ExitCode::Usage as i32);
                }
            }
        }
        Resolution::Plugin { name, args } => {
            // Re-resolve name → path (resolve() only established existence).
            // Vanished between resolve and here (unlikely race) → fall
            // through to the Python passthrough like any unknown command.
            if let Some(path) = commands::plugins::find_plugin(&name) {
                if globals.verbose {
                    eprintln!(
                        "noo-cli(rust) v{}: plugin `{}` → {}",
                        env!("CARGO_PKG_VERSION"),
                        name,
                        path.display()
                    );
                }
                // Same environment contract as native commands: repo .env
                // loaded, already-exported vars win. exec() replaces the
                // process — stdio, signals, and the exit code pass through
                // to/from the shim untouched.
                envfile::ensure_repo_env();
                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new(&path).args(&args).exec();
                fail(
                    globals.json,
                    ExitCode::Generic,
                    "plugin_exec_failed",
                    &format!("failed to exec plugin {}: {err}", path.display()),
                    None,
                );
            }
            // fall through to the passthrough exec below.
        }
        Resolution::Passthrough | Resolution::Addon { .. } => {
            // A top-level word the registry, the plugin path AND the
            // python-only list all disown is an unknown command. Answer it
            // here with suggestions — Python's "No such command 'status'"
            // was the only diagnostic before (2026-09-01), and on a
            // python-less box it was "python_cli_not_found".
            // (An add-on lookup that found nothing names its words from the
            // global-flag-stripped stream: a `--gateway <url>` value ahead of
            // the command is not the command.)
            let words_src: &[String] = addon_words.as_deref().unwrap_or(&argv);
            let cmd_words: Vec<&str> = words_src
                .iter()
                .map(String::as_str)
                .filter(|t| !t.starts_with('-') && *t != "completions")
                .collect();
            if let Some(head) = cmd_words.first() {
                let known_group = NATIVE.iter().any(|(entry, _)| entry.first() == Some(head));
                if !known_group && !PYTHON_ONLY_GROUPS.contains(head) {
                    let sugg = suggest(head);
                    let hint = if sugg.is_empty() {
                        "`noo --help` lists the command groups".to_string()
                    } else {
                        format!("did you mean: {}", sugg.join(", "))
                    };
                    fail(
                        globals.json,
                        ExitCode::Usage,
                        "unknown_command",
                        &format!("unknown command `{head}`"),
                        Some(&hint),
                    );
                }
                // Known group, unknown second word: Python may still own it
                // (a handful of flags/variants do), so only hint, then
                // fall through as before.
                if known_group && cmd_words.len() >= 2 && !globals.json {
                    let sub = cmd_words[1];
                    let owned = NATIVE
                        .iter()
                        .any(|(entry, _)| entry.first() == Some(head) && entry.get(1) == Some(&sub));
                    if !owned {
                        let near: Vec<String> = NATIVE
                            .iter()
                            .filter(|(entry, _)| entry.first() == Some(head))
                            .filter(|(entry, _)| entry.get(1).is_some_and(|w| w.starts_with(sub) || edit_distance(w, sub) <= 2))
                            .map(|(entry, _)| format!("noo {}", entry.join(" ")))
                            .take(4)
                            .collect();
                        if !near.is_empty() {
                            eprintln!("noo: no native `{head} {sub}` — did you mean: {}", near.join(", "));
                        }
                    }
                }
            }
        }
    }

    // Not ours (or a native handler returned Unhandled, or Python-served help)
    // — replace this process with the Python CLI. But a bare KNOWN GROUP on
    // a box with no Python (standalone default) used to die with
    // "python_cli_not_found" — the least helpful possible answer to `noo
    // cluster` (finding #56). Render the native group help instead.
    // Finding #56, third shape: a bare KNOWN GROUP on a python-less box
    // gets the native group help as a PREFIX — then falls through so the
    // passthrough's own tailored diagnosis (python-only vs developer-only
    // vs unknown, each with its pinned wording and the exit-2
    // python_cli_not_found contract) stays the authority. The first two
    // shapes (early-exit 0, then early-exit 2 with a homemade note) each
    // broke a different pinned contract; the help is additive, never a
    // replacement.
    if passthrough::python_cli_path().is_none() {
        let cmd_words: Vec<String> = argv
            .iter()
            .filter(|t| !t.starts_with('-'))
            .cloned()
            .collect();
        // An unknown subcommand/flag on a native group gets only the error
        // (CLI_STYLE_GUIDE: an error is a `✗` line plus guidance); the full
        // usage dump is for a bare group.
        let misuse = passthrough::native_group_misuse(&argv).is_some() && argv.len() > 1;
        if let Some(head) = cmd_words.first().filter(|_| !misuse) {
            if NATIVE.iter().any(|(entry, _)| entry.first() == Some(&head.as_str())) {
                print_native_help_for(&cmd_words);
            }
        }
    }
    if let Err(msg) = passthrough::exec_python(&argv) {
        fail(
            globals.json,
            ExitCode::Usage,
            "python_cli_not_found",
            &msg,
            Some(&passthrough::no_python_hint(&argv)),
        );
    }
}

#[cfg(test)]
mod tests {

/// Positionals a syntax string promises: `<x>` or `[<x>]` tokens up to the
/// first flag. `[--days <n>]` is a flag with a value, not a positional.
fn positional_count(syntax: &str) -> usize {
    syntax
        .split_whitespace()
        .take_while(|t| !t.trim_start_matches('[').starts_with('-'))
        .filter(|t| t.trim_start_matches('[').starts_with('<'))
        .count()
}

fn extra_of(words: &[&str], skip: usize) -> String {
    words[skip..].join(" ")
}

/// Files whose printed hints the arity test checks.
const SOURCES: &[(&str, &str)] = &[
    ("main.rs", include_str!("main.rs")),
    ("commands/cluster.rs", include_str!("commands/cluster.rs")),
    ("commands/cluster_provision.rs", include_str!("commands/cluster_provision.rs")),
    ("commands/provision.rs", include_str!("commands/provision.rs")),
    ("commands/approval.rs", include_str!("commands/approval.rs")),
    ("commands/pki.rs", include_str!("commands/pki.rs")),
    ("commands/recall.rs", include_str!("commands/recall.rs")),
    ("commands/models.rs", include_str!("commands/models.rs")),
];

    /// The FLAG half of hint honesty: every `--flag` a hint shows must
    /// exist in that command's usage syntax, across every file in
    /// `src/commands`. Its sibling `hint_commands_name_real_verbs_with_real_arity`
    /// checks POSITIONAL arity over the `SOURCES` list above; between them a
    /// hint cannot promise a verb, an argument or a flag the CLI does not
    /// take. Both exist because hand-typed guidance drifted twice in one day
    /// (2026-09-03: `cluster status` advertised a `place-model <node>
    /// <backend> <model>` shape, and six more hints named flags that were
    /// never parsed).
    #[test]
    fn hint_flags_exist_in_the_usage_table() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("commands");
        let re = regex_lite("\"noo ([a-z][a-z0-9-]*(?: [a-z][a-z0-9-]*)*)((?: [^\"]*)?)\"");
        let mut bad = Vec::new();
        for entry in std::fs::read_dir(&root).unwrap().flatten() {
            let path = entry.path();
            if path.extension().map(|e| e != "rs").unwrap_or(true) {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            for (lineno, line) in src.lines().enumerate() {
                if !(line.contains("ui::guide") || line.contains("ui::hint") || line.contains("ui::cmd(") || line.trim_start().starts_with("(\"noo ") || line.trim_start().starts_with("(&format!(\"noo ")) {
                    continue;
                }
                for (words, tail) in re(line) {
                    let toks: Vec<&str> = words.split(' ').collect();
                    // longest NATIVE prefix
                    let mut best: Option<&'static [&'static str]> = None;
                    for (entry, _) in super::NATIVE {
                        if entry.len() <= toks.len() && entry.iter().zip(&toks).all(|(a, b)| a == b) && best.is_none_or(|e| entry.len() > e.len()) {
                            best = Some(entry);
                        }
                    }
                    let Some(entry) = best else {
                        bad.push(format!("{file}:{}: `noo {words}` is not a native command", lineno + 1));
                        continue;
                    };
                    let (syntax, _) = super::usage::lookup(entry).unwrap_or(("", ""));
                    const GLOBALS: &[&str] = &["--json", "--quiet", "--verbose", "--color", "--gateway", "--timeout", "--token", "--instance", "--watch", "--help"];
                    for flag in tail.split_whitespace().filter(|t| t.starts_with("--")) {
                        let flag = flag.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
                        if GLOBALS.contains(&flag) {
                            continue;
                        }
                        if !syntax.contains(flag) {
                            bad.push(format!("{file}:{}: `noo {} {flag}` — flag not in usage `{}`", lineno + 1, entry.join(" "), syntax));
                        }
                    }
                }
            }
        }
        assert!(bad.is_empty(), "guidance drift:\n{}", bad.join("\n"));
    }

    /// Tiny matcher for the guidance test (no regex crate): returns
    /// (command words, tail) for each `"noo …"` literal on a line.
    fn regex_lite(_pattern: &str) -> impl Fn(&str) -> Vec<(String, String)> {
        |line: &str| {
            let mut out = Vec::new();
            let mut rest = line;
            while let Some(i) = rest.find("\"noo ") {
                let after = &rest[i + 1..];
                let Some(end) = after.find('\"') else { break };
                let lit = &after[..end];
                rest = &after[end + 1..];
                // words: leading lowercase tokens; tail: from the first
                // token that is a placeholder/flag/format arg onward.
                let mut words = Vec::new();
                let mut tail = String::new();
                for (n, tok) in lit.split(' ').enumerate() {
                    if n == 0 {
                        continue; // "noo"
                    }
                    let is_word = !tok.is_empty() && tok.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') && !tok.starts_with('-');
                    if tail.is_empty() && is_word {
                        words.push(tok.to_string());
                    } else {
                        if !tail.is_empty() {
                            tail.push(' ');
                        }
                        tail.push_str(tok);
                    }
                }
                if !words.is_empty() {
                    out.push((words.join(" "), tail));
                }
            }
            out
        }
    }

    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    /// Every registry group sits in exactly one help section and has a
    /// tagline — a new group that forgets either renders under "Other"
    /// with a blank description, which this catches at test time.
    #[test]
    fn every_group_has_a_section_and_a_tagline() {
        let mut groups: Vec<&str> = Vec::new();
        for (words, _) in NATIVE {
            if is_hidden_native(words) {
                continue;
            }
            if let Some(g) = words.first() {
                if !groups.contains(g) {
                    groups.push(g);
                }
            }
        }
        for g in &groups {
            let n = GROUP_SECTIONS.iter().filter(|(_, m)| m.contains(g)).count();
            assert_eq!(n, 1, "group `{g}` must appear in exactly one GROUP_SECTIONS entry (found {n})");
            assert!(!group_desc(g).is_empty(), "group `{g}` has no GROUP_DESC tagline");
        }
        for (_, members) in GROUP_SECTIONS {
            for m in *members {
                assert!(groups.contains(m), "GROUP_SECTIONS names `{m}`, which is not a registry group");
            }
        }
    }

    #[test]
    fn suggestions_find_commands_and_near_groups() {
        let s = suggest("status");
        assert!(s.iter().any(|x| x == "noo cluster status"), "{s:?}");
        assert!(s.len() <= 6, "{s:?}");
        assert!(suggest("stac").iter().any(|x| x == "noo stack"));
        assert!(suggest("clustr").iter().any(|x| x == "noo cluster"));
        assert!(suggest("sec").iter().any(|x| x == "noo security"));
        assert!(suggest("zzzzzzzz").is_empty());
        assert_eq!(edit_distance("mesh", "mesh"), 0);
        assert_eq!(edit_distance("mesh", "mash"), 1);
    }

    /// The usage table (`usage.rs`) and the dispatch registry describe the
    /// same command set, 1:1 — a command without usage renders bare in
    /// `--help`, and usage for a command that does not exist is a lie.
    /// Every `noo …` command STRING printed as a hint must name a real verb
    /// and not invent positional arguments it does not take. `noo cluster
    /// status` told the operator to run `noo cluster place-model <node>
    /// <backend> <model>`; the verb takes only a model, and the arity error
    /// then fell through to "no Python CLI" (host8, 2026-09-03).
    #[test]
    fn hint_commands_name_real_verbs_with_real_arity() {
        let usage: std::collections::BTreeMap<Vec<&str>, usize> = usage::USAGE
            .iter()
            .map(|(w, syntax, _)| (w.to_vec(), positional_count(syntax)))
            .collect();
        let mut verbs: Vec<&Vec<&str>> = usage.keys().collect();
        verbs.sort_by_key(|v| std::cmp::Reverse(v.len()));
        let mut bad = Vec::new();
        for (file, src) in SOURCES {
            for line in src.lines() {
                for frag in line.split('"').skip(1).step_by(2) {
                    let Some(rest) = frag.strip_prefix("noo ") else { continue };
                    // Only command-shaped strings: no prose, no punctuation.
                    if rest.contains(':') || rest.contains(',') || rest.contains('{') { continue; }
                    let words: Vec<&str> = rest.split_whitespace().collect();
                    let Some(v) = verbs.iter().find(|v| words.len() >= v.len()
                        && words[..v.len()].iter().zip(v.iter()).all(|(a, b)| a == b)) else { continue };
                    let positional = positional_count(&extra_of(&words, v.len()));
                    let declared = usage[*v];
                    if positional > declared {
                        bad.push(format!("{file}: `noo {rest}` — {} takes {declared} positional(s)", v.join(" ")));
                    }
                }
            }
        }
        assert!(bad.is_empty(), "hints promise arguments the verb does not take:\n  {}", bad.join("\n  "));
    }

    /// `security service-key <Tab>` offers the third-level verbs, and the
    /// walk stops at the command: `provision <Tab>` is an argument position.
    #[test]
    fn completion_walks_verbs_to_any_depth() {
        let g = crate::Globals { json: false, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: false };
        let w = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let third = completion_candidates(&g, &w(&["security", "service-key"]));
        for v in ["provision", "rotate", "revoke", "retire", "list"] {
            assert!(third.iter().any(|x| x == v), "{v} missing from {third:?}");
        }
        // Two-word commands keep offering their arguments, not a verb list.
        let leaf = completion_candidates(&g, &w(&["cluster", "status"]));
        assert!(!leaf.iter().any(|x| x == "status"), "a leaf must not re-offer itself: {leaf:?}");
    }

    #[test]
    fn retired_and_plumbing_cluster_verbs_are_hidden_and_issue_token_is_gone() {
        for w in [&["node", "fetch"][..], &["cluster", "clean-node"], &["cluster", "exec"],
                  &["cluster", "reconnect"], &["cluster", "sync-models"]] {
            assert!(NATIVE.iter().any(|(e, _)| e == &w), "{w:?} must still dispatch");
            assert!(is_hidden_native(w), "{w:?} must be out of customer help");
        }
        assert!(
            !NATIVE.iter().any(|(e, _)| e == &["cluster", "issue-token"]),
            "cluster issue-token printed a token nothing validates; it was removed"
        );
        assert!(!is_hidden_native(&["cluster", "status"]));
    }

    #[test]
    fn usage_table_matches_registry_exactly() {
        let native: std::collections::BTreeSet<Vec<&str>> =
            NATIVE.iter().map(|(w, _)| w.to_vec()).collect();
        let mut seen: std::collections::BTreeSet<Vec<&str>> = Default::default();
        for (w, syntax, about) in usage::USAGE {
            assert!(seen.insert(w.to_vec()), "duplicate usage entry for {w:?}");
            assert!(native.contains(*w), "usage entry {w:?} names no native command");
            assert!(!about.is_empty(), "usage entry {w:?} has no description");
            assert!(about.chars().count() <= 90, "usage description for {w:?} is too long");
            assert!(!about.ends_with('.'), "usage description for {w:?} ends with a period");
            assert!(!syntax.starts_with("noo "), "usage syntax for {w:?} repeats the binary name");
        }
        let missing: Vec<_> = native
            .difference(&seen)
            .filter(|w| !HIDDEN_NO_USAGE.contains(&w.as_slice()))
            .collect();
        assert!(missing.is_empty(), "native commands without usage: {missing:?}");
        // A hidden command still dispatches, and must not be listed.
        for w in HIDDEN_NO_USAGE {
            assert!(native.contains(*w), "hidden entry {w:?} names no native command");
            assert!(!seen.contains(*w), "hidden entry {w:?} must have no usage row");
        }
    }

    /// Vendor/CI verbs and the `pki rotate` alias stay dispatchable but are
    /// off the customer's help and tab-completion; their usage rows say so.
    #[test]
    fn vendor_only_verbs_and_the_pki_rotate_alias_are_hidden_but_still_dispatch() {
        let hidden: [&[&str]; 5] = [
            &["security", "entitlement", "keygen"],
            &["security", "entitlement", "issue"],
            &["security", "release-sign"],
            &["security", "addon-lock", "sign"],
            &["security", "pki", "rotate"],
        ];
        for h in hidden {
            assert!(is_hidden_native(h), "{h:?} must be hidden");
            assert!(NATIVE.iter().any(|(w, _)| *w == h), "{h:?} must still dispatch");
            let (_, about) = usage::lookup(h).expect("usage row");
            assert!(about.starts_with("Hidden:"), "{h:?}: {about}");
        }
        for shown in [&["security", "entitlement", "install"][..], &["security", "release-verify"], &["security", "addon-lock", "verify"], &["security", "pki", "issue"], &["security", "user", "enable"]] {
            assert!(!is_hidden_native(shown), "{shown:?} is customer-facing");
            assert!(NATIVE.iter().any(|(w, _)| *w == shown), "{shown:?}");
        }
    }

    /// `a` is a prefix of `b` iff `b` starts with all of `a`'s words in order.
    /// Under first-match dispatch this is the reachability hazard: if an
    /// earlier entry's words prefix a later entry's, the later entry can never
    /// be selected (the earlier one always matches first).
    fn is_prefix(a: &[&str], b: &[&str]) -> bool {
        a.len() <= b.len() && a.iter().zip(b).all(|(x, y)| x == y)
    }

    /// `mesh` resolves natively wherever the command word sits relative to
    /// a leading global flag.
    #[test]
    fn mesh_aliases_mesh() {
        for words in [vec!["stack", "status"], vec!["--json", "stack", "status"]] {
            let (_, r) = resolve_with(&argv(&words), |_| false);
            match r {
                Resolution::Native { prefix, .. } => {
                    assert_eq!(prefix, &["stack", "status"]);
                }
                other => panic!("mesh did not resolve natively: {other:?}"),
            }
        }
    }

    // ── Part 2.1: registry integrity ────────────────────────────────────────

    /// No two registry entries share the exact same command words. Duplicate
    /// prefixes would make the second entry's handler dead code (first-match
    /// always picks the earlier one). Aliases that point at the same handler
    /// are fine BECAUSE they use distinct words (e.g. `approval pending` vs
    /// `approval list`).
    #[test]
    fn registry_has_no_duplicate_prefixes() {
        for (i, (a, _)) in NATIVE.iter().enumerate() {
            for (b, _) in NATIVE.iter().skip(i + 1) {
                assert_ne!(
                    a, b,
                    "duplicate NATIVE prefix {:?} — the later copy is unreachable",
                    a
                );
            }
        }
    }

    /// Matching rule enforced: dispatch is FIRST-match over the registry in
    /// declaration order. An entry `j` is reachable only if no EARLIER entry
    /// `i` (< j) has words that are a prefix of `j`'s words — otherwise every
    /// argv that would select `j` also matches `i`, and `i` wins. So we assert
    /// that for every ordered pair (earlier, later), the earlier entry's words
    /// are NOT a prefix of the later entry's words. (Equality is the
    /// degenerate case, already covered above; this is the strict-prefix
    /// hazard, e.g. `["cluster"]` before `["cluster","status"]`.)
    #[test]
    fn registry_has_no_shadowed_entries() {
        for (i, (earlier, _)) in NATIVE.iter().enumerate() {
            for (later, _) in NATIVE.iter().skip(i + 1) {
                assert!(
                    !is_prefix(earlier, later),
                    "entry {:?} is shadowed by earlier entry {:?} \
                     (first-match makes it unreachable)",
                    later,
                    earlier
                );
            }
        }
    }

    /// Every registry entry has at least one command word (an empty prefix
    /// would match — and thus capture — everything).
    #[test]
    fn registry_entries_are_nonempty() {
        for (words, _) in NATIVE {
            assert!(!words.is_empty(), "empty NATIVE prefix would swallow all argv");
        }
    }

    // ── Part 2.2: resolve() dispatch ────────────────────────────────────────

    fn native_prefix(r: &Resolution) -> Option<&[&str]> {
        match r {
            Resolution::Native { prefix, .. } => Some(prefix),
            _ => None,
        }
    }

    #[test]
    fn resolves_single_word_native() {
        let (_, r) = resolve(&argv(&["health"]));
        assert_eq!(native_prefix(&r), Some(&["health"][..]));
        // rest carries the FULL post-flag token stream, incl. the command words.
        assert_eq!(r, Resolution::Native { prefix: &["health"], rest: argv(&["health"]) });
    }

    #[test]
    fn resolves_two_word_native() {
        let (_, r) = resolve(&argv(&["cluster", "status"]));
        assert_eq!(native_prefix(&r), Some(&["cluster", "status"][..]));
    }

    #[test]
    fn resolves_json_flag_before_command() {
        let (g, r) = resolve(&argv(&["--json", "jobs", "list"]));
        assert!(g.json);
        assert_eq!(native_prefix(&r), Some(&["jobs", "list"][..]));
        // The consumed global flag is gone from rest; command words remain.
        assert_eq!(r, Resolution::Native { prefix: &["jobs", "list"], rest: argv(&["jobs", "list"]) });
    }

    #[test]
    fn resolves_global_flag_interleaved() {
        // A global flag sitting BETWEEN command words is still consumed and the
        // command still resolves.
        let (g, r) = resolve(&argv(&["jobs", "--json", "list"]));
        assert!(g.json);
        assert_eq!(native_prefix(&r), Some(&["jobs", "list"][..]));
    }

    #[test]
    fn add_node_is_no_longer_a_command() {
        // `cluster add-node` was DELETED from the registry 2026-09-03
        // item 2): it drove the ansible/ tree removed in 3695e129, so every
        // mode but `--probe-only` ended in `playbook_failed`. Enrollment is
        // `noo enroll` / `noo cluster provision` / a bootstrap token. The
        // registry must not grow it back under any spelling.
        assert!(
            !NATIVE
                .iter()
                .any(|(entry, _)| entry.first() == Some(&"cluster") && entry.get(1) == Some(&"add-node")),
            "cluster add-node is retired — do not re-register it"
        );
        let (_, r) = resolve(&argv(&["cluster", "add-node", "x"]));
        assert_eq!(r, Resolution::Passthrough);
    }

    #[test]
    fn unported_command_passes_through() {
        // No DEV_ONLY surface is left, so any unregistered word stands in.
        // (`db revision`/`debug` filled this role until 2026-09-03; `tui`
        // before 2026-08-16; `voice status` before WP-V.)
        let (_, r) = resolve(&argv(&["no-such-group"]));
        // Offered to the add-on lookup first; with no add-on group of that
        // name it is the unknown command it always was.
        assert_eq!(r, Resolution::Addon { rest: argv(&["no-such-group"]) });
    }

    #[test]
    fn voice_commands_resolve_native() {
        // WP-V: the voice group is native (thin HTTP to the gateway voice
        // routes) — no longer PY_ONLY passthrough.
        for words in [
            &["voice", "transcribe"][..],
            &["voice", "synthesize"][..],
            &["voice", "speak"][..],
            &["voice", "status"][..],
            &["voice", "voices"][..],
        ] {
            let (_, r) = resolve(&argv(words));
            assert_eq!(native_prefix(&r), Some(words), "expected {words:?} native");
        }
        // Bare `voice` (group help) still goes to Python.
        let (_, r) = resolve(&argv(&["voice"]));
        assert_eq!(r, Resolution::Passthrough);
    }

    #[test]
    fn bare_group_word_passes_through() {
        // `cluster` alone is not a registry entry (every cluster command has a
        // second word), so it is not native — Python owns the group help.
        let (_, r) = resolve(&argv(&["cluster"]));
        assert_eq!(r, Resolution::Passthrough);
    }

    #[test]
    fn resolves_version() {
        assert_eq!(resolve(&argv(&["--version"])).1, Resolution::Version);
        assert_eq!(resolve(&argv(&["-V"])).1, Resolution::Version);
    }

    #[test]
    fn resolves_help() {
        assert_eq!(resolve(&argv(&[])).1, Resolution::Help);
        assert_eq!(resolve(&argv(&["--help"])).1, Resolution::Help);
        assert_eq!(resolve(&argv(&["-h"])).1, Resolution::Help);
    }

    #[test]
    fn help_after_native_words_is_native() {
        // A group prefix, an exact command, and an exact command with args
        // all render native help — never Python (a broken venv must not turn
        // `--help` into a traceback, 2026-08-16).
        for toks in [
            vec!["security", "--help"],
            vec!["security", "pki", "-h"],
            vec!["security", "pki", "issue", "--help"],
            vec!["security", "pki", "issue", "HOST3", "--help"],
        ] {
            let (_, r) = resolve(&argv(&toks));
            let want: Vec<String> = toks[..toks.len() - 1].iter().map(|s| s.to_string()).collect();
            assert_eq!(r, Resolution::HelpFor { words: want }, "toks={toks:?}");
        }
    }

    #[test]
    fn help_for_unknown_words_still_passes_through() {
        // Unknown words keep Typer's rich help. (`plugins --help` is native
        // since WP-PL gave the group a native subcommand; `debug --help`
        // was the example here until the group's 2026-09-03 retirement.)
        assert_eq!(
            resolve(&argv(&["no-such-group", "--help"])).1,
            Resolution::Addon { rest: argv(&["no-such-group", "--help"]) }
        );
        assert_eq!(
            resolve(&argv(&["definitely-not-a-command", "--help"])).1,
            Resolution::Addon { rest: argv(&["definitely-not-a-command", "--help"]) }
        );
    }

    #[test]
    fn tui_is_native_and_retired() {
        // Retired 2026-08-16: answered natively (pointer message), never
        // exec'd through to Python.
        let (_, r) = resolve(&argv(&["tui"]));
        assert!(matches!(r, Resolution::Native { prefix, .. } if prefix == ["tui"]));
    }

    #[test]
    fn version_wins_over_help_and_native() {
        // `--version` is checked before help and before the registry.
        let (_, r) = resolve(&argv(&["--version", "health"]));
        assert_eq!(r, Resolution::Version);
    }

    #[test]
    fn gateway_and_timeout_flags_consumed() {
        let (g, r) = resolve(&argv(&["-G", "https://x:1", "--timeout", "5", "jobs", "list"]));
        assert_eq!(g.gateway_override.as_deref(), Some("https://x:1"));
        assert_eq!(g.timeout_secs, Some(5));
        assert_eq!(native_prefix(&r), Some(&["jobs", "list"][..]));
    }

    #[test]
    fn gateway_long_flag_consumed() {
        let (g, _) = resolve(&argv(&["--gateway", "http://h:8080", "health"]));
        assert_eq!(g.gateway_override.as_deref(), Some("http://h:8080"));
    }

    #[test]
    fn unknown_flag_after_native_prefix_stays_native() {
        // Dispatch still routes to the handler; the UNKNOWN flag is the
        // handler's problem (it returns Unhandled → main falls through). We
        // only assert the routing decision here, not the handler outcome.
        let (_, r) = resolve(&argv(&["health", "--bogus-flag"]));
        assert_eq!(
            r,
            Resolution::Native { prefix: &["health"], rest: argv(&["health", "--bogus-flag"]) }
        );
    }

    #[test]
    fn unknown_flag_before_command_fails_match_and_passes_through() {
        // A stray token ahead of the command words breaks the prefix match, so
        // the whole thing goes to Python (which owns the full surface).
        let (_, r) = resolve(&argv(&["--bogus", "health"]));
        assert_eq!(r, Resolution::Passthrough);
    }

    #[test]
    fn alias_prefixes_resolve_to_their_own_entry() {
        // `approval pending` is a distinct-words alias of `approval list`; it
        // must resolve as its own native entry (not shadowed, not passthrough).
        let (_, r) = resolve(&argv(&["approval", "pending"]));
        assert_eq!(native_prefix(&r), Some(&["approval", "pending"][..]));
    }

    #[test]
    fn rotate_all_is_not_shadowed_by_rotate() {
        // Words are matched EXACTLY, so "rotate-all" != "rotate": the
        // earlier `security pki rotate` entry must not capture rotate-all
        // argv, and each must resolve to its own entry (WP-B1).
        let (_, r) = resolve(&argv(&["security", "pki", "rotate-all", "--no-reload"]));
        assert_eq!(native_prefix(&r), Some(&["security", "pki", "rotate-all"][..]));
        let (_, r) = resolve(&argv(&["security", "pki", "rotate", "n1", "10.0.0.1"]));
        assert_eq!(native_prefix(&r), Some(&["security", "pki", "rotate"][..]));
    }

    #[test]
    fn security_local_commands_resolve() {
        for words in [
            &["security", "generate-secret"][..],
            &["security", "scan"][..],
            &["security", "trust-ca"][..],
            &["security", "untrust-ca"][..],
        ] {
            let (_, r) = resolve(&argv(words));
            assert_eq!(native_prefix(&r), Some(words), "expected {words:?} native");
        }
        // The `security` HTTP surface (user/team/org/…) is native too since
        // WP-A3 — its own registry block; spot-check it resolves natively.
        let (_, r) = resolve(&argv(&["security", "user", "list"]));
        assert_eq!(native_prefix(&r), Some(&["security", "user", "list"][..]));
    }

    #[test]
    fn approval_decide_entries_resolve_native() {
        // WP-4a: the write side is native now — `approval approve/deny` must
        // dispatch to the registry (thin HTTP to /decide), not passthrough.
        let (_, r) = resolve(&argv(&["approval", "approve", "req-1"]));
        assert_eq!(native_prefix(&r), Some(&["approval", "approve"][..]));
        let (_, r) = resolve(&argv(&["approval", "deny", "req-1", "--reason", "no"]));
        assert_eq!(native_prefix(&r), Some(&["approval", "deny"][..]));
    }

    // ── WP-PL: plugin-shim fallback (resolve_with keeps this pure — the
    // shim-existence predicate is injected, no filesystem involved). ────────

    #[test]
    fn plugin_fallback_fires_for_unknown_word_with_shim() {
        let (_, r) = resolve_with(&argv(&["frob", "a", "b"]), |n| n == "frob");
        assert_eq!(
            r,
            Resolution::Plugin { name: "frob".into(), args: argv(&["a", "b"]) }
        );
    }

    #[test]
    fn plugin_fallback_without_shim_goes_to_the_addon_lookup() {
        let (_, r) = resolve_with(&argv(&["frob", "a"]), |_| false);
        assert_eq!(r, Resolution::Addon { rest: argv(&["frob", "a"]) });
    }

    #[test]
    fn native_always_wins_over_plugin() {
        // Even with a noo-health shim present, builtins come first (git rule).
        let (_, r) = resolve_with(&argv(&["health"]), |_| true);
        assert_eq!(native_prefix(&r), Some(&["health"][..]));
    }

    #[test]
    fn reserved_words_are_never_plugins() {
        // Native group first words (`cluster` bare = Python group help), the
        // PY_ONLY/DEV_ONLY-gated groups, and `py` (the Python CLI shim) must
        // pass through even when a same-named shim exists.
        for word in ["cluster", "voice", "plugins", "mcp", "py"] {
            let (_, r) = resolve_with(&argv(&[word]), |_| true);
            assert_eq!(r, Resolution::Passthrough, "`{word}` must not dispatch as a plugin");
        }
    }

    #[test]
    fn plugin_args_come_from_original_argv_after_the_word() {
        // Globals BEFORE the word are noo's (consumed); everything AFTER the
        // word goes to the plugin verbatim — including tokens that collide
        // with our global flags, like --json.
        let a = argv(&["--json", "frob", "--json", "-v", "x"]);
        let (g, r) = resolve_with(&a, |n| n == "frob");
        assert!(g.json);
        assert_eq!(
            r,
            Resolution::Plugin { name: "frob".into(), args: argv(&["--json", "-v", "x"]) }
        );
    }

    #[test]
    fn plugin_lookup_skips_flag_like_words() {
        // A leading unknown flag is not a plugin candidate (and help/version
        // are handled before the plugin step).
        let (_, r) = resolve_with(&argv(&["--bogus", "health"]), |_| true);
        assert_eq!(r, Resolution::Passthrough);
    }

    #[test]
    fn plugins_list_is_native() {
        // The `plugins list` registry entry (WP-PL) — must dispatch natively,
        // not as a plugin and not to Python.
        let (_, r) = resolve_with(&argv(&["plugins", "list"]), |_| true);
        assert_eq!(native_prefix(&r), Some(&["plugins", "list"][..]));
    }

    #[test]
    fn models_refresh_resolves_native() {
        // WP-R: `models refresh` left PY_ONLY and went native — it must
        // dispatch to the registry entry, flags riding along in rest.
        let (_, r) = resolve(&argv(&["models", "refresh", "--backend", "vllm", "--llm"]));
        assert_eq!(native_prefix(&r), Some(&["models", "refresh"][..]));
    }

    #[test]
    fn mcp_entries_resolve_native() {
        // WP-M: `mcp tools` (hub-backed listing) and `mcp external-setup`
        // (local token mint) are native; other `mcp …` argv still passes
        // through to Python.
        let (_, r) = resolve(&argv(&["mcp", "tools"]));
        assert_eq!(native_prefix(&r), Some(&["mcp", "tools"][..]));
        let (_, r) = resolve(&argv(&["mcp", "external-setup", "--save"]));
        assert_eq!(native_prefix(&r), Some(&["mcp", "external-setup"][..]));
        let (_, r) = resolve(&argv(&["mcp"]));
        assert_eq!(native_prefix(&r), None);
    }

    #[test]
    fn handler_for_resolves_every_registry_prefix() {
        // handler_for must succeed for every native prefix resolve() can emit
        // (it panics otherwise) — guards the resolve→main handler lookup.
        for (words, _) in NATIVE {
            let _ = handler_for(words);
        }
    }
}
