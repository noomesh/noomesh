// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Agent routes — multi-agent collaboration, workflows, personas, coding, skills.
//!
//! Native Rust: coding tasks (SQL), workflow definitions, persona list/get (YAML config),
//!   skills list/info/rescan/run (filesystem + node-agent proxy),
//!   agent roles (hardcoded definitions)
//! NATS delegation: multi-agent collaboration, workflow execution, persona chat

use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post},
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::AppState;
use super::{AppJson, AppError, AppResult};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── Multi-agent: Native Rust (roles: hardcoded — ported 2026-03-31) ──
        .route("/api/agents/roles", get(agents_roles))
        .route("/api/agents/collaborate", post(agents_collaborate))
        // ── Agent messaging: Native Rust (JetStream + SQL) ──
        .route("/api/agents/messages", get(messages_list).post(messages_send))
        .route("/api/agents/messages/{id}", get(messages_get))
        .route("/api/agents/messages/{id}/ack", post(messages_ack))
        .route("/api/agents/threads", get(threads_list))
        // cold storage of expired mail (operator-only; sealed unless ?decrypt=true, which is audited).
        .route("/api/agents/archive", get(archive_list))
        .route("/api/agents/archive/{month}", get(archive_export))
        // the exceptions to the owner boundary.
        .route("/api/agents/trust", get(trust_list).post(trust_add))
        .route("/api/agents/trust/remove", post(trust_remove))
        // which of a person's windows are alive.
        .route("/api/agents/presence", get(presence_list))
        // who am I on this session — the address others message.
        .route("/api/agents/whoami", get(whoami))
        // name this session (`<account>/<type>-<name>`) so others can address it.
        .route("/api/agents/name", post(agent_name))
        .route("/api/agents/keys/{agent}", get(keys_get).put(keys_put))
        .route("/api/agents/keys/review", get(keys_review))
        .route("/api/agent/run", post(agent_run))

        // ── Workflows: Native Rust (hardcoded definitions) ──
        .route("/api/workflows", get(workflows_list))
        // ── Workflows: NATS delegation (execution needs Python agent) ──
        .route("/api/workflows/run", post(workflows_run))

        // ── Personas: Native Rust (YAML config) ──
        .route("/api/persona/", get(persona_list))
        .route("/api/persona/{persona_id}", get(persona_get))
        // /api/persona/{id}/chat REMOVED. It delegated to worker.persona.chat,
        // whose handler imports noomesh.agents.persona_registry — a module
        // that does not exist. Live probe before removal:
        //   POST /api/persona/default/chat
        //     -> 400 {"error":"No module named 'noomesh.agents.persona_registry'"}
        // It has never worked in this form, and it leaked an internal module
        // path to API clients. Persona LISTING is native Rust and unaffected;
        // if persona chat is wanted it is a feature to build on the existing
        // persona config + coordinator::run, not a route to keep 400ing.

        // ── Coding: Native Rust (SQL) ──
        // Submission stays Python (it drives the coding manager, which owns
        // the Claude Code subprocess lifecycle). Explicit route because the
        // /api/{*path} catchall it used to arrive through is gone —
        // delegation is declared, never implicit.
        .route("/api/coding/task", post(super::delegation::delegate_post("worker.api.coding.task")))
        .route("/api/coding/tasks", get(coding_tasks))
        .route("/api/coding/tasks/{task_id}", get(coding_get_task))

        // ── Skills: Native Rust (filesystem scan + node-agent proxy) ──
        .route("/api/skills/list", get(skills_list))
        .route("/api/skills/{skill_name}/info", get(skills_info))
        .route("/api/skills/{skill_name}/run", post(skills_run))
        .route("/api/skills/rescan", post(skills_rescan))
}

// ═══════════════════════════════════════════════════════════════
// Agent roles — native Rust (hardcoded definitions)
//
// Mirrors the Python AgentOrchestrator.list_roles() which returns
// the AGENT_SPECS from multi_agent.py. Since these are static
// definitions, we hardcode them here.
// ═══════════════════════════════════════════════════════════════

/// GET /api/agents/roles — list available agent roles.
///
/// Returns the predefined agent role definitions matching the Python
/// `AgentRole` enum and `AGENT_SPECS` dict in `agents/multi_agent.py`.
async fn agents_roles() -> AppJson {
    let roles = vec![
        json!({
            "role": "researcher",
            "system_prompt": "You are a research specialist. Your role is to:\n- Gather information from multiple sources\n- Verify facts and cross-reference data\n- Summarize findings clearly and concisely\n- Identify knowledge gaps and uncertainties\nBe thorough but efficient in your research.",
            "preferred_tools": ["web_search", "local_files"],
            "max_tool_loops": 5,
        }),
        json!({
            "role": "coder",
            "system_prompt": "You are a coding expert. Your role is to:\n- Write clean, efficient, well-documented code\n- Follow best practices and design patterns\n- Consider edge cases and error handling\n- Optimize for readability and maintainability\nFocus on quality over speed.",
            "preferred_tools": ["python_exec", "local_files"],
            "max_tool_loops": 4,
        }),
        json!({
            "role": "analyst",
            "system_prompt": "You are a data analyst. Your role is to:\n- Analyze data patterns and trends\n- Generate insights and recommendations\n- Create clear visualizations when helpful\n- Identify correlations and anomalies\nBe precise and data-driven in your analysis.",
            "preferred_tools": ["python_exec"],
            "max_tool_loops": 4,
        }),
        json!({
            "role": "planner",
            "system_prompt": "You are a planning specialist. Your role is to:\n- Break down complex tasks into steps\n- Identify dependencies and ordering\n- Allocate work appropriately\n- Anticipate potential issues\nCreate actionable, structured plans.",
            "preferred_tools": [],
            "max_tool_loops": 2,
        }),
        json!({
            "role": "reviewer",
            "system_prompt": "You are a code reviewer. Your role is to:\n- Identify bugs, security issues, and code smells\n- Suggest improvements for clarity and performance\n- Verify adherence to requirements\n- Provide constructive feedback\nBe thorough but respectful in reviews.",
            "preferred_tools": ["local_files"],
            "max_tool_loops": 2,
        }),
    ];

    Json(json!({"roles": roles}))
}

// ═══════════════════════════════════════════════════════════════
// Persona handlers — native Rust (reads from YAML config cache)
// ═══════════════════════════════════════════════════════════════

/// GET /api/persona/ — list all registered personas from YAML config.
///
/// Reads the `personas` section of noomesh.yaml. Each entry has at minimum
/// `persona_id` and `name`.
///
/// `active` used to be a hardcoded `false` on every entry — the doc comment
/// even admitted the reason ("always false in Rust since coordinators live in
/// Python"), which is an admission that the field was an assertion about a
/// process this one cannot see, not a measurement. A persona in active use was
/// reported as inactive. It is now `null` with an `active_detail` reason.
async fn persona_list(
    State(state): State<Arc<AppState>>,
) -> AppResult {
    let config = state.config_yaml.read().await;

    let personas = config
        .get("personas")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    let summaries: Vec<Value> = personas
        .iter()
        .filter_map(|p| {
            let pid = p.get("persona_id").and_then(|v| v.as_str())?;
            Some(json!({
                "persona_id": pid,
                "name": p.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                "occupation": p.get("occupation").and_then(|v| v.as_str()).unwrap_or(""),
                "active": Value::Null,
            }))
        })
        .collect();

    Ok(Json(json!({
        "personas": summaries,
        "active_detail": "null — persona activation lives in the Python \
            coordinator's session state and is not observable from the Rust \
            gateway. Previously reported as false for every persona.",
    })))
}

/// GET /api/persona/{persona_id} — get a specific persona definition.
///
/// Returns the full persona dict from the `personas` config array, or 404.
async fn persona_get(
    State(state): State<Arc<AppState>>,
    Path(persona_id): Path<String>,
) -> AppResult {
    let config = state.config_yaml.read().await;

    let personas = config
        .get("personas")
        .and_then(|p| p.as_array());

    let persona = personas.and_then(|arr| {
        arr.iter().find(|p| {
            p.get("persona_id").and_then(|v| v.as_str()) == Some(persona_id.as_str())
        })
    });

    match persona {
        Some(p) => Ok(Json(p.clone())),
        None => Err(AppError::NotFound(format!("Persona '{}' not found", persona_id))),
    }
}

// ═══════════════════════════════════════════════════════════════
// Skills handlers — native Rust (filesystem scan of manifest.yml)
// ═══════════════════════════════════════════════════════════════

/// Skill directory candidates — Docker first, then local dev.
const SKILLS_BUILTIN_CANDIDATES: &[&str] = &[
    "/app/skills/builtins",
    "skills/builtins",
];

/// Resolve the user skills directory from env or default.
fn user_skills_dir() -> String {
    std::env::var("NOO_SKILLS_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        format!("{}/.noo/skills", home)
    })
}

/// Scan a single directory for skill manifest.yml files.
/// Returns a vec of (name, parsed manifest Value).
async fn scan_skills_dir(dir: &str) -> Vec<Value> {
    let mut skills = Vec::new();
    let path = std::path::Path::new(dir);
    if !path.exists() {
        return skills;
    }

    let mut read_dir = match tokio::fs::read_dir(path).await {
        Ok(rd) => rd,
        Err(_) => return skills,
    };

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        if !entry.path().is_dir() {
            continue;
        }
        let manifest_path = entry.path().join("manifest.yml");
        if !manifest_path.exists() {
            continue;
        }
        let dir_name = entry.file_name().to_string_lossy().to_string();
        match tokio::fs::read_to_string(&manifest_path).await {
            Ok(contents) => {
                match serde_yaml::from_str::<Value>(&contents) {
                    Ok(manifest) => {
                        let name = manifest
                            .get("name")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .unwrap_or_else(|| dir_name.clone());
                        let version = manifest
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0.0.1");
                        let description = manifest
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let author = manifest
                            .get("author")
                            .and_then(|v| v.as_str())
                            .unwrap_or("noo-builtin");

                        skills.push(json!({
                            "name": name,
                            "version": version,
                            "description": description,
                            "author": author,
                            "skill_dir": entry.path().to_string_lossy(),
                        }));
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %manifest_path.display(),
                            error = %e,
                            "Failed to parse skill manifest"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    path = %manifest_path.display(),
                    error = %e,
                    "Failed to read skill manifest"
                );
            }
        }
    }

    skills
}

/// Scan all skill directories and return combined results.
async fn scan_all_skills() -> Vec<Value> {
    let mut all_skills = Vec::new();

    // Scan builtin directories
    for candidate in SKILLS_BUILTIN_CANDIDATES {
        if std::path::Path::new(candidate).exists() {
            all_skills.extend(scan_skills_dir(candidate).await);
            break; // Use first existing candidate
        }
    }

    // Scan user skills directory
    let user_dir = user_skills_dir();
    all_skills.extend(scan_skills_dir(&user_dir).await);

    all_skills
}

/// GET /api/skills/list — list available skills from filesystem scan.
///
/// Scans builtin and user skill directories for manifest.yml files.
/// Returns skill name, version, description, author for each.
async fn skills_list() -> AppResult {
    let skills = scan_all_skills().await;
    Ok(Json(json!({ "skills": skills })))
}

/// GET /api/skills/{skill_name}/info — get a specific skill's manifest.
///
/// Scans skill directories and returns the full manifest for the named skill,
/// including inputs, outputs, container config, and permissions.
async fn skills_info(
    Path(skill_name): Path<String>,
) -> AppResult {
    // Scan directories to find the skill
    for candidate in SKILLS_BUILTIN_CANDIDATES {
        if let Some(info) = find_skill_manifest(candidate, &skill_name).await {
            return Ok(Json(info));
        }
    }

    let user_dir = user_skills_dir();
    if let Some(info) = find_skill_manifest(&user_dir, &skill_name).await {
        return Ok(Json(info));
    }

    Err(AppError::NotFound(format!("Skill '{}' not found", skill_name)))
}

/// Find a specific skill manifest by name in a directory.
async fn find_skill_manifest(dir: &str, skill_name: &str) -> Option<Value> {
    let path = std::path::Path::new(dir);
    if !path.exists() {
        return None;
    }

    let mut read_dir = tokio::fs::read_dir(path).await.ok()?;
    while let Ok(Some(entry)) = read_dir.next_entry().await {
        if !entry.path().is_dir() {
            continue;
        }
        let manifest_path = entry.path().join("manifest.yml");
        if !manifest_path.exists() {
            continue;
        }
        let dir_name = entry.file_name().to_string_lossy().to_string();
        if let Ok(contents) = tokio::fs::read_to_string(&manifest_path).await {
            if let Ok(manifest) = serde_yaml::from_str::<Value>(&contents) {
                let name = manifest
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| dir_name.clone());
                if name == skill_name {
                    return Some(json!({
                        "name": name,
                        "version": manifest.get("version").and_then(|v| v.as_str()).unwrap_or("0.0.1"),
                        "description": manifest.get("description").and_then(|v| v.as_str()).unwrap_or(""),
                        "author": manifest.get("author").and_then(|v| v.as_str()).unwrap_or("noo-builtin"),
                        "inputs": manifest.get("inputs").cloned().unwrap_or(json!({})),
                        "outputs": manifest.get("outputs").cloned().unwrap_or(json!({})),
                        "container": manifest.get("container").cloned().unwrap_or(json!({})),
                        "permissions": manifest.get("permissions").cloned().unwrap_or(json!({})),
                        "skill_dir": entry.path().to_string_lossy(),
                    }));
                }
            }
        }
    }
    None
}

/// POST /api/skills/rescan — re-scan skills directories.
///
/// Forces a fresh scan of all skill directories and returns updated count.
async fn skills_rescan() -> AppResult {
    let skills = scan_all_skills().await;
    let count = skills.len();
    tracing::info!(count, "Skills rescan complete");
    Ok(Json(json!({ "status": "ok", "skills": count })))
}

// ═══════════════════════════════════════════════════════════════
// Skills run — native Rust (node-agent proxy)
//
// Pattern: read manifest from filesystem, resolve a node from
// NATS KV mesh_nodes, POST the container spec to the node-agent's
// /api/skills/run endpoint, return the result.
// ═══════════════════════════════════════════════════════════════

/// Docker network names mapped from skill permission levels.
const SKILL_NETWORK_MAP: &[(&str, &str)] = &[
    ("none", "none"),
    ("restricted", "noo-skill-restricted"),
    ("full", "bridge"),
    ("host", "host"),
];

fn resolve_skill_network(network: &str) -> &str {
    SKILL_NETWORK_MAP
        .iter()
        .find(|(k, _)| *k == network)
        .map(|(_, v)| *v)
        .unwrap_or("none")
}

#[derive(Deserialize)]
struct SkillRunRequest {
    #[serde(default)]
    inputs: Value,
    node_id: Option<String>,
}

/// POST /api/skills/{skill_name}/run — execute a skill container on a node agent.
///
/// Native Rust implementation (replaces NATS delegation to Python):
/// 1. Read the skill manifest from filesystem
/// 2. Pick a target node (explicit or least-loaded from NATS KV)
/// 3. Build the container spec (image, command, env, limits, network, GPU)
/// 4. POST to node-agent /api/skills/run
/// 5. Return the result (stdout parsed as JSON, or error)
async fn skills_run(
    State(state): State<Arc<AppState>>,
    Path(skill_name): Path<String>,
    Json(body): Json<SkillRunRequest>,
) -> AppResult {
    // 1. Find the skill manifest
    let manifest = find_full_skill_manifest(&skill_name).await
        .ok_or_else(|| AppError::NotFound(format!("Skill '{}' not found", skill_name)))?;

    // Extract container config from manifest
    let container_cfg = manifest.get("container").cloned().unwrap_or(json!({}));
    let image = container_cfg.get("image").and_then(|v| v.as_str())
        .unwrap_or("noo-sandbox-base:latest");
    // Migration shim: base image renamed noo-skill-base → noo-sandbox-base
    // (2026-07). Stale user manifests in ~/.noo/skills may still carry the
    // old tag, which no longer exists on any node — map it to the new name.
    let image = if image == "noo-skill-base:latest" { "noo-sandbox-base:latest" } else { image };
    let command: Vec<String> = container_cfg.get("command")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["python".into(), "/skill/run.py".into()]);
    let timeout = container_cfg.get("timeout").and_then(|v| v.as_u64()).unwrap_or(60);
    let memory_limit = container_cfg.get("memory_limit").and_then(|v| v.as_str())
        .unwrap_or("256m");
    let network_perm = container_cfg.get("network").and_then(|v| v.as_str())
        .unwrap_or("restricted");
    let gpu = container_cfg.get("gpu").and_then(|v| v.as_bool()).unwrap_or(false);

    // Validate required inputs
    let inputs_schema = manifest.get("inputs").cloned().unwrap_or(json!({}));
    if let Some(schema_map) = inputs_schema.as_object() {
        let input_obj = body.inputs.as_object();
        let mut missing = Vec::new();
        for (param_name, param_def) in schema_map {
            let required = param_def.get("required")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if required {
                let present = input_obj
                    .map(|m| m.contains_key(param_name))
                    .unwrap_or(false);
                if !present {
                    missing.push(param_name.clone());
                }
            }
        }
        if !missing.is_empty() {
            return Err(AppError::BadRequest(
                format!("Missing required inputs: {}", missing.join(", "))
            ));
        }
    }

    // 2. Resolve target node
    let (node_id, agent_url) = resolve_skill_node(&state, body.node_id.as_deref(), gpu).await?;

    // 3. Build container spec payload (matches Python SkillExecutor.run_container)
    let container_name = format!("noo-skill-{}-{}", skill_name, &uuid_hex()[..8]);
    let network_mode = resolve_skill_network(network_perm);

    // Bind-mount the skill directory so `python /skill/run.py` can resolve —
    // read-only on the node-agent side. Mirrors Python's SandboxExecutor
    // (`{skill_dir: "/skill"}`). The bind source must be a path on the TARGET
    // node's HOST filesystem: inside the gateway container the tree lives at
    // /app/skills, so NOO_SKILLS_HOST_DIR (set by compose to the host path of
    // ./skills) rewrites that prefix before the spec is sent.
    let volumes = manifest
        .get("skill_dir")
        .and_then(|v| v.as_str())
        .map(|dir| json!({ translate_skill_dir(dir): "/skill" }))
        .unwrap_or_else(|| json!({}));

    // Preferred transport: ship the skill directory inline as base64 files.
    // The volumes bind-mount above only resolves on the controller's own
    // host filesystem — remote nodes fail with "bind source path does not
    // exist". New node-agents materialize `files` at /skill and ignore
    // `volumes`; old agents ignore the unknown `files` field and keep the
    // legacy bind-mount behavior (controller-local only).
    let files = match manifest.get("skill_dir").and_then(|v| v.as_str()) {
        Some(dir) => collect_skill_files(dir).await,
        None => None,
    };

    let mut payload = json!({
        "image": image,
        "command": command,
        "container_name": container_name,
        "env": { "SKILL_INPUT": serde_json::to_string(&body.inputs).unwrap_or_default() },
        "memory_limit": memory_limit,
        "network_mode": network_mode,
        "gpu": gpu,
        "timeout": timeout,
        "volumes": volumes,
    });
    if let Some(files) = files {
        payload["files"] = Value::Object(files);
    }

    tracing::info!(
        skill = %skill_name,
        image = %image,
        container = %container_name,
        node_id = %node_id,
        "skill_container_start",
    );

    // 4. POST to node-agent /api/skills/run
    let req = crate::node_link::NodeLink::for_base(&agent_url)
        .request(reqwest::Method::POST, "/api/skills/run")
        .json(&payload)
        .timeout(std::time::Duration::from_secs(timeout + 30));

    let t0 = std::time::Instant::now();

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let duration_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let data = resp.json::<Value>().await.unwrap_or(json!({}));

            let exit_code = data.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(-1);
            let stdout = data.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
            let stderr = data.get("stderr").and_then(|v| v.as_str()).unwrap_or("");
            let container_id = data.get("container_id").and_then(|v| v.as_str())
                .unwrap_or(&container_name);

            if exit_code != 0 {
                tracing::warn!(
                    container = %container_name,
                    exit_code,
                    "skill_container_nonzero",
                );
                return Ok(Json(json!({
                    "success": false,
                    "error": format!("Container exited with code {}: {}",
                        exit_code, truncate_str(stderr, 500)),
                    "duration_ms": duration_ms,
                    "container_id": container_id,
                    "node_id": node_id,
                })));
            }

            // Parse stdout as JSON output
            let output = parse_skill_output(stdout);

            tracing::info!(
                container = %container_name,
                duration_ms = format!("{:.1}", duration_ms),
                skill = %skill_name,
                "skill_container_success",
            );

            Ok(Json(json!({
                "success": true,
                "output": output,
                "duration_ms": duration_ms,
                "container_id": container_id,
                "node_id": node_id,
            })))
        }
        Ok(resp) => {
            let duration_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let status = resp.status().as_u16();
            let body_text = resp.text().await.unwrap_or_default();
            tracing::error!(
                container = %container_name,
                status,
                "skill_container_error",
            );
            Ok(Json(json!({
                "success": false,
                "error": format!("Node agent returned {status}: {body_text}"),
                "duration_ms": duration_ms,
                "node_id": node_id,
            })))
        }
        Err(e) => {
            let duration_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let is_timeout = e.is_timeout();
            tracing::error!(
                container = %container_name,
                error = %e,
                timeout = is_timeout,
                "skill_container_error",
            );
            let msg = if is_timeout {
                format!("Container timed out after {}s", timeout)
            } else {
                format!("Container execution failed: {e}")
            };
            Ok(Json(json!({
                "success": false,
                "error": msg,
                "duration_ms": duration_ms,
                "node_id": node_id,
            })))
        }
    }
}

/// Resolve a target node for skill execution.
///
/// If `node_id` is provided, resolves its agent URL directly.
/// Otherwise, picks the least-loaded node from NATS KV mesh_nodes
/// that supports GPU (if required by the skill).
async fn resolve_skill_node(
    state: &AppState,
    node_id: Option<&str>,
    needs_gpu: bool,
) -> Result<(String, String), AppError> {
    if let Some(nid) = node_id {
        let url = crate::node_link::NodeLink::for_node(state, nid).await?.base().to_string();
        return Ok((nid.to_string(), url));
    }

    // Auto-select: scan NATS KV for least-loaded node
    let agents = super::admin::all_node_agents(state).await;
    if agents.is_empty() {
        return Err(AppError::NotFound("No nodes available for skill execution".into()));
    }

    // Score each node: read current_load from KV, filter by GPU if needed
    let mut best: Option<(String, String, f64)> = None;

    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        for (nid, url, _hostname) in &agents {
            if let Ok(Some(entry)) = kv.get(nid.as_str()).await {
                if let Ok(data) = serde_json::from_slice::<Value>(&entry) {
                    // Skip nodes that are not online
                    let status = data.get("status").and_then(|v| v.as_str()).unwrap_or("");
                    if status != "online" { continue; }

                    // Filter by GPU if the skill needs it
                    if needs_gpu {
                        let has_gpu = data.get("gpu_model")
                            .and_then(|v| v.as_str())
                            .map(|g| !g.is_empty() && g != "none")
                            .unwrap_or(false);
                        if !has_gpu { continue; }
                    }

                    let load = data.get("current_load").and_then(|v| v.as_f64()).unwrap_or(1.0);
                    if best.as_ref().map(|(_, _, bl)| load < *bl).unwrap_or(true) {
                        best = Some((nid.clone(), url.clone(), load));
                    }
                }
            }
        }
    }

    match best {
        Some((nid, url, _)) => Ok((nid, url)),
        None => {
            // Fallback: just use first available agent
            let (nid, url, _) = agents.into_iter().next().unwrap();
            Ok((nid, url))
        }
    }
}

/// Find a skill manifest with full details (including container config).
/// Searches builtin and user directories, returning the complete
/// parsed YAML as a serde_json::Value.
async fn find_full_skill_manifest(skill_name: &str) -> Option<Value> {
    for candidate in SKILLS_BUILTIN_CANDIDATES {
        if let Some(m) = find_skill_manifest_full(candidate, skill_name).await {
            return Some(m);
        }
    }
    let user_dir = user_skills_dir();
    find_skill_manifest_full(&user_dir, skill_name).await
}

/// Search a directory for a skill by name and return its full manifest.
async fn find_skill_manifest_full(dir: &str, skill_name: &str) -> Option<Value> {
    let path = std::path::Path::new(dir);
    if !path.exists() { return None; }
    let mut read_dir = tokio::fs::read_dir(path).await.ok()?;
    while let Ok(Some(entry)) = read_dir.next_entry().await {
        if !entry.path().is_dir() { continue; }
        let manifest_path = entry.path().join("manifest.yml");
        if !manifest_path.exists() { continue; }
        let dir_name = entry.file_name().to_string_lossy().to_string();
        if let Ok(contents) = tokio::fs::read_to_string(&manifest_path).await {
            if let Ok(manifest) = serde_yaml::from_str::<Value>(&contents) {
                let name = manifest
                    .get("name").and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| dir_name.clone());
                if name == skill_name {
                    // Record where the skill lives so skills_run can bind-mount
                    // it into the container (parity with the list scan and the
                    // Python SandboxExecutor).
                    let mut manifest = manifest;
                    if let Some(obj) = manifest.as_object_mut() {
                        obj.insert(
                            "skill_dir".into(),
                            json!(entry.path().to_string_lossy()),
                        );
                    }
                    return Some(manifest);
                }
            }
        }
    }
    None
}


/// Rewrite a container-local skill path onto the host filesystem.
///
/// The gateway container mounts the repo's `skills/` tree at `/app/skills`;
/// a node-agent bind mount needs the HOST location of the same tree, which
/// compose exports as `NOO_SKILLS_HOST_DIR`. Unset (host-run dev) or
/// non-matching paths pass through unchanged.
fn translate_skill_dir(dir: &str) -> String {
    if let Ok(host_root) = std::env::var("NOO_SKILLS_HOST_DIR") {
        if !host_root.is_empty() {
            if let Some(rest) = dir.strip_prefix("/app/skills") {
                return format!("{}{}", host_root.trim_end_matches('/'), rest);
            }
        }
    }
    dir.to_string()
}

/// Caps for inline skill files — must match the node-agent's
/// MaxSkillFiles / MaxSkillFileBytes (node-agent-go/internal/docker/skills.go).
const MAX_SKILL_FILES: usize = 64;
const MAX_SKILL_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Read a skill directory into an inline-files map: relative path →
/// base64 content. Skips hidden entries (dotfiles/dotdirs) and any file
/// larger than the per-payload cap; stops adding once total decoded size
/// or file count would exceed the node-agent's limits. Returns None when
/// the directory can't be read or yields no files (callers then rely on
/// the legacy volumes bind-mount).
async fn collect_skill_files(skill_dir: &str) -> Option<serde_json::Map<String, Value>> {
    use base64::Engine as _;

    let root = std::path::PathBuf::from(skill_dir);
    let mut files = serde_json::Map::new();
    let mut total: u64 = 0;
    // Iterative walk (skill dirs are tiny — manifest.yml + run.py + maybe a lib/).
    let mut stack = vec![root.clone()];

    while let Some(dir) = stack.pop() {
        let mut read_dir = tokio::fs::read_dir(&dir).await.ok()?;
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue; // hidden files/dirs
            }
            let path = entry.path();
            let meta = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue; // symlinks etc.
            }
            if meta.len() > MAX_SKILL_FILE_BYTES || total + meta.len() > MAX_SKILL_FILE_BYTES {
                tracing::warn!(path = %path.display(), size = meta.len(),
                    "skill file exceeds inline cap, skipping");
                continue;
            }
            if files.len() >= MAX_SKILL_FILES {
                tracing::warn!(dir = %skill_dir, "skill file count cap reached, truncating");
                break;
            }
            let rel = match path.strip_prefix(&root) {
                Ok(r) => r.to_string_lossy().to_string(),
                Err(_) => continue,
            };
            match tokio::fs::read(&path).await {
                Ok(bytes) => {
                    total += bytes.len() as u64;
                    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
                    files.insert(rel, Value::String(encoded));
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "skill file read failed");
                }
            }
        }
    }

    if files.is_empty() { None } else { Some(files) }
}

/// Parse container stdout as JSON, falling back to raw text.
fn parse_skill_output(stdout: &str) -> Value {
    let stdout = stdout.trim();
    if stdout.is_empty() {
        return json!({});
    }
    match serde_json::from_str::<Value>(stdout) {
        Ok(v) if v.is_object() => v,
        Ok(v) => json!({"result": v}),
        Err(_) => json!({"raw_output": stdout}),
    }
}

/// Generate a hex string for unique container names.
fn uuid_hex() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    // Mix timestamp nanos with thread ID for uniqueness
    let thread_id = format!("{:?}", std::thread::current().id());
    let raw = format!("{:016x}{}", ts, thread_id);
    raw.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(32)
        .collect()
}

// ═══════════════════════════════════════════════════════════════
// Coding tasks — native SQL via sqlx
// ═══════════════════════════════════════════════════════════════

/// GET /api/coding/tasks — list all coding tasks with status.
///
/// Coding tasks are stored in noo_coding_tasks by the Python CodingTaskManager.
/// This handler reads them directly from Postgres, avoiding the NATS round-trip.
async fn coding_tasks(State(state): State<Arc<AppState>>) -> AppResult {
    let rows = sqlx::query_as::<_, (
        String,                                // task_id
        String,                                // description
        String,                                // channel
        String,                                // conversation_id
        String,                                // status
        Option<String>,                        // result
        Option<String>,                        // error
        Option<f64>,                           // elapsed_seconds
        Value,                                 // files_edited
        Option<chrono::DateTime<chrono::Utc>>, // started_at
        Option<chrono::DateTime<chrono::Utc>>, // completed_at
    )>(
        "SELECT id, COALESCE(description, ''), COALESCE(channel, ''), \
                COALESCE(conversation_id, ''), COALESCE(status, 'pending'), \
                result, error, elapsed_seconds, \
                COALESCE(files_edited, '[]'::jsonb), \
                started_at, completed_at \
         FROM noo_coding_tasks \
         ORDER BY started_at DESC NULLS LAST"
    )
    .fetch_all(&state.db)
    .await;

    // Graceful degradation: if the table doesn't exist yet, return empty list
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("does not exist") || msg.contains("relation") {
                tracing::debug!("noo_coding_tasks table not found, returning empty list");
                return Ok(Json(json!({"tasks": []})));
            }
            return Err(AppError::Internal(format!("Database error: {e}")));
        }
    };

    let tasks: Vec<Value> = rows.iter().map(|(
        task_id, description, channel, conversation_id, status,
        result, error, elapsed_seconds, files_edited,
        started_at, completed_at,
    )| {
        json!({
            "task_id": task_id,
            "description": truncate_str(description, 200),
            "channel": channel,
            "conversation_id": conversation_id,
            "status": status,
            "result": result.as_deref().map(|r| truncate_str(r, 4000)),
            "error": error,
            "elapsed_seconds": elapsed_seconds,
            "files_edited": files_edited,
            "started_at": started_at,
            "completed_at": completed_at,
        })
    }).collect();

    Ok(Json(json!({"tasks": tasks})))
}

/// GET /api/coding/tasks/{task_id} — detailed info for a specific coding task.
async fn coding_get_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
) -> AppResult {
    let row = sqlx::query_as::<_, (
        String,                                // task_id
        String,                                // description
        String,                                // channel
        String,                                // conversation_id
        String,                                // status
        Option<String>,                        // result (full, not truncated)
        Option<String>,                        // error
        Option<f64>,                           // elapsed_seconds
        Value,                                 // files_edited
        Option<chrono::DateTime<chrono::Utc>>, // started_at
        Option<chrono::DateTime<chrono::Utc>>, // completed_at
    )>(
        "SELECT id, COALESCE(description, ''), COALESCE(channel, ''), \
                COALESCE(conversation_id, ''), COALESCE(status, 'pending'), \
                result, error, elapsed_seconds, \
                COALESCE(files_edited, '[]'::jsonb), \
                started_at, completed_at \
         FROM noo_coding_tasks WHERE id = $1"
    )
    .bind(&task_id)
    .fetch_optional(&state.db)
    .await;

    let row = match row {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("does not exist") || msg.contains("relation") {
                return Err(AppError::NotFound(format!("Task {task_id} not found")));
            }
            return Err(AppError::Internal(format!("Database error: {e}")));
        }
    };

    let (id, description, channel, conversation_id, status,
         result, error, elapsed_seconds, files_edited,
         started_at, completed_at) = match row {
        Some(r) => r,
        None => return Err(AppError::NotFound(format!("Task {task_id} not found"))),
    };

    Ok(Json(json!({
        "task_id": id,
        "description": description,
        "channel": channel,
        "conversation_id": conversation_id,
        "status": status,
        "result": result,
        "error": error,
        "elapsed_seconds": elapsed_seconds,
        "files_edited": files_edited,
        "started_at": started_at,
        "completed_at": completed_at,
    })))
}

/// Truncate a string to approximately the specified max byte length (char-boundary safe).
fn truncate_str(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }
}

// ═══════════════════════════════════════════════════════════════
// Workflows — native Rust (hardcoded definitions)
// ═══════════════════════════════════════════════════════════════

/// GET /api/workflows — list available workflow definitions.
///
/// GET /api/workflows — the built-in templates.
///
/// These used to be hard-coded JSON here AND declared as Python objects in
/// workflows/workflow.py. Two declarations of one fact, free to drift, with
/// the list endpoint and the run endpoint able to disagree silently.
/// `crate::workflows` is now the single definition and this reads from it.
async fn workflows_list() -> AppJson {
    Json(crate::workflows::list_json())
}

/// POST /api/workflows/run — execute a multi-step workflow.
async fn workflows_run(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let id = body
        .get("workflow_id")
        .or_else(|| body.get("name"))
        .or_else(|| body.get("workflow_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let params = body
        .get("params")
        .or_else(|| body.get("inputs"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    match crate::workflows::run_workflow(&state, id, &params).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(e)).into_response(),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::auth::{ClusterKind, ClusterNode, RequesterCtx, Role};

    fn jwt(sub: &str, role: Role, harness: Option<&str>) -> Option<Extension<RequesterCtx>> {
        Some(Extension(RequesterCtx {
            sub: sub.into(),
            scopes: role.legacy_scopes().iter().map(|s| s.to_string()).collect(),
            role,
            harness: harness.map(str::to_string),
            act: None,
        }))
    }

    /// `harness` names the credential class. A plain user token is
    /// `api` — the CLI, the dashboard and a script are indistinguishable,
    /// so naming one would be the same guess the finding is about.
    #[test]
    fn harness_comes_from_the_credential_class() {
        assert_eq!(caller(&jwt("alice", Role::User, None), &None).harness, "api");
        assert_eq!(
            caller(&jwt("alice", Role::User, Some("mcp-external:acme")), &None).harness,
            "mcp-external:acme"
        );
        let internal = Some(Extension(ClusterNode("mcp-local".into(), ClusterKind::Internal)));
        assert_eq!(caller(&None, &internal).harness, "internal:mcp-local");
        let node = Some(Extension(ClusterNode("host3".into(), ClusterKind::Node)));
        assert_eq!(caller(&None, &node).harness, "node:host3");
        assert_eq!(caller(&None, &None).harness, "unknown");
    }

    /// M21b: broadcast fans out to every connected peer, so only callers
    /// the stack already trusts fleet-wide may ask for it.
    #[test]
    fn only_privileged_callers_may_broadcast() {
        let may_broadcast = |c: Caller| c.check_broadcast("*").is_ok();
        assert!(!may_broadcast(caller(&jwt("alice", Role::User, None), &None)));
        assert!(may_broadcast(caller(&jwt("alice", Role::Operator, None), &None)));
        assert!(may_broadcast(caller(
            &None,
            &Some(Extension(ClusterNode("gateway".into(), ClusterKind::Internal)))
        )));
        // A node holds the fleet secret, which every node holds — the
        // threat model for this whole tracker. It addresses agents by name.
        assert!(!may_broadcast(caller(
            &None,
            &Some(Extension(ClusterNode("host3".into(), ClusterKind::Node)))
        )));
        assert!(!may_broadcast(caller(&None, &None)));
        // A named recipient is unaffected for everyone.
        assert!(caller(&jwt("alice", Role::User, None), &None)
            .check_broadcast("host3/claude-code-1")
            .is_ok());
    }

    fn unique_test_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "noo-skill-files-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn collect_skill_files_reads_tree_and_skips_hidden() {
        let dir = unique_test_dir("basic");
        std::fs::write(dir.join("run.py"), b"print('hi')").unwrap();
        std::fs::write(dir.join("manifest.yml"), b"name: t").unwrap();
        std::fs::write(dir.join(".hidden"), b"secret").unwrap();
        std::fs::create_dir_all(dir.join("lib")).unwrap();
        std::fs::write(dir.join("lib/util.py"), b"pass").unwrap();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join(".git/config"), b"x").unwrap();

        let files = collect_skill_files(dir.to_str().unwrap()).await.unwrap();
        assert!(files.contains_key("run.py"));
        assert!(files.contains_key("manifest.yml"));
        assert!(files.contains_key("lib/util.py"));
        assert!(!files.contains_key(".hidden"));
        assert!(!files.keys().any(|k| k.starts_with(".git")));
        assert_eq!(files.len(), 3);

        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(files["run.py"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded, b"print('hi')");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn collect_skill_files_skips_oversized() {
        let dir = unique_test_dir("oversize");
        std::fs::write(dir.join("run.py"), b"ok").unwrap();
        std::fs::write(
            dir.join("huge.bin"),
            vec![0u8; (MAX_SKILL_FILE_BYTES + 1) as usize],
        )
        .unwrap();

        let files = collect_skill_files(dir.to_str().unwrap()).await.unwrap();
        assert!(files.contains_key("run.py"));
        assert!(!files.contains_key("huge.bin"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn collect_skill_files_missing_dir_is_none() {
        assert!(collect_skill_files("/nonexistent/skill/dir").await.is_none());
    }

    // ── User-tier agent messaging: ack and thread seat ───────────────

    #[test]
    fn a_user_acks_only_mail_addressed_to_their_own_identity() {
        let a = user_caller("alice");
        assert!(may_ack(&a, "alice/claude-s1"));
        assert!(may_ack(&a, "alice"));
        assert!(!may_ack(&a, "bob"));
        assert!(!may_ack(&a, "bob/claude-s1"));
        assert!(!may_ack(&a, ""));
        // A connection owns its own address; it does not own the bare account
        // address (documented limit: such mail is acked by the bare account).
        let conn = user_caller("alice/claude-s1");
        assert!(may_ack(&conn, "alice/claude-s1"));
        assert!(!may_ack(&conn, "alice"));
    }

    #[test]
    fn a_user_cannot_send_as_an_agent_they_do_not_own() {
        let a = user_caller("alice");
        assert!(a.acting_agent(Some("bob")).is_err());
        assert!(a.acting_agent(Some("bob/s1")).is_err());
        assert_eq!(a.acting_agent(None).unwrap(), "alice");
        assert!(a.check_broadcast("*").is_err());
        assert!(a.check_broadcast("broadcast").is_err());
    }

    #[test]
    fn thread_seat_fails_closed_on_a_database_error() {
        assert!(!seat_in_thread::<String>(Ok(Some(false))).unwrap());
        assert!(seat_in_thread::<String>(Ok(Some(true))).unwrap());
        // An unused thread id may be claimed.
        assert!(seat_in_thread::<String>(Ok(None)).unwrap());
        assert!(seat_in_thread::<String>(Err("connection reset".into())).is_err());
    }

    // ── who may act as, and read for, whom ──────────────

    fn user_caller(sub: &str) -> Caller {
        caller(&jwt(sub, Role::User, None), &None)
    }

    #[test]
    fn an_account_may_act_as_its_own_connections() {
        let alice = user_caller("alice");
        assert!(alice.owns("alice"));
        assert!(alice.owns("alice/laptop"));
        // The widening is confined to the caller's own prefix.
        assert!(!alice.owns("someone-else"));
        assert!(!alice.owns("someone-else/session"));
        assert_eq!(alice.acting_agent(Some("alice/laptop")).unwrap(), "alice/laptop");
        assert!(alice.acting_agent(Some("other/session")).is_err());
    }

    /// The trap the review caught, asserted at the level an operator cares
    /// about: not "the predicate returns false" but "session 2 cannot read
    /// session 1's mail". `may_read` is built on `owns`, so widening one
    /// widens the other in the same commit, silently.
    #[test]
    fn sibling_sessions_are_strangers() {
        let s1 = user_caller("alice/claude-s1");
        assert!(s1.owns("alice/claude-s1"));
        assert!(!s1.owns("alice/laptop"), "a session must not act as its sibling");
        assert!(!s1.owns("alice"), "a session must not act as the account that minted it");

        let siblings_mail = json!({ "from": "alice/laptop", "to": "alice/claude-s2" });
        assert!(!s1.may_read(&siblings_mail), "a session must not READ its siblings' mail");

        let own_mail = json!({ "from": "alice/laptop", "to": "alice/claude-s1" });
        assert!(s1.may_read(&own_mail), "…but its own inbox is its own");

        // The account still sees everything under it — one person, one
        // history — which is the other half of the asymmetry.
        assert!(user_caller("alice").may_read(&siblings_mail));
    }

    /// The fan-out rule, decided rather than left to whoever wrote the
    /// query: mail addressed to a bare ACCOUNT reaches every connection
    /// under it, mail addressed to one CONNECTION is that connection's
    /// alone. The day the MCP door started minting connections, this is
    /// what kept "to: owner" from vanishing for all of owner's windows.
    #[test]
    fn mail_to_the_account_fans_out_but_mail_to_a_session_does_not() {
        let s1 = user_caller("owner/claude-s1");
        let s2 = user_caller("owner/laptop");
        let acct = user_caller("owner");

        let to_account = json!({ "from": "other/agent", "to": "owner" });
        assert!(s1.may_read(&to_account), "a session reads mail addressed to its account");
        assert!(s2.may_read(&to_account), "…every session does — that is fan-out");
        assert!(acct.may_read(&to_account));

        let to_s1 = json!({ "from": "other/agent", "to": "owner/claude-s1" });
        assert!(s1.may_read(&to_s1));
        assert!(!s2.may_read(&to_s1), "mail to one session is not a sibling's to read");
        assert!(acct.may_read(&to_s1), "the account owns every connection under it");

        // Not a general prefix rule: a foreign account's mail stays foreign.
        assert!(!s1.may_read(&json!({ "from": "x/y", "to": "other" })));
        // And `to == sub` is the plain ownership case, not fan-out.
        assert!(!user_caller("ownerx").may_read(&to_account));
    }

    /// Read state is per READER. Pinned as
    /// source because the repo needs a database: `list` must compute
    /// unread from the per-reader table when a reader is present, and
    /// `mark_read` must write that table. Drop either and the first
    /// window to ack clears a message for every sibling again.
    #[test]
    fn unread_and_ack_are_per_reader() {
        let repo = include_str!("../repo/agent_messages.rs");
        let list = repo.split("pub async fn list(").nth(1).expect("list");
        let list = &list[..list.find("\n}").unwrap()];
        assert!(list.contains("noo_agent_message_reads") && list.contains("x.reader ="),
            "unread must be computed from the per-reader reads table");
        let ack = repo.split("pub async fn mark_read(").nth(1).expect("mark_read");
        let ack = &ack[..ack.find("\n}").unwrap()];
        assert!(ack.contains("INSERT INTO noo_agent_message_reads"),
            "ack must record the reader, not only flip the message's read_at");
        // And both routes hand the ACTING identity in as the reader.
        // Runtime-assembled needles: literals here would match this test's
        // own source and pass whether or not the routes do it.
        let routes = include_str!("agents.rs");
        let list_needle = ["reader: ", "reader.as_deref()"].concat();
        let ack_needle = ["mark_read(&state.db, &id, ", "&reader)"].concat();
        assert!(routes.matches(list_needle.as_str()).count() >= 1, "list route must pass its reader");
        assert!(routes.matches(ack_needle.as_str()).count() >= 1, "ack route must pass its reader");
    }

    /// The default is the caller's OWN mail, operator role or not. Only a
    /// caller with no acting identity (the shared cluster token) sees
    /// everything by default; `all=true` widens for a privileged caller and
    /// is refused for anyone else.
    #[test]
    fn list_scope_defaults_to_own_mail_and_all_is_operator_only() {
        // privileged WITH a sub (an operator's session): scoped by default
        assert_eq!(list_sees_everything(true, true, false), Ok(false));
        // …and widened only on request
        assert_eq!(list_sees_everything(true, true, true), Ok(true));
        // cluster token (privileged, no sub): unchanged, sees everything
        assert_eq!(list_sees_everything(true, false, false), Ok(true));
        assert_eq!(list_sees_everything(true, false, true), Ok(true));
        // non-privileged: scoped, and all=true is a 403, not a silent narrow
        assert_eq!(list_sees_everything(false, true, false), Ok(false));
        assert!(list_sees_everything(false, true, true).is_err());
        assert!(list_sees_everything(false, false, true).is_err());
    }

    /// Source pin: both list routes must consult the one rule, and the
    /// threads listing must go through the repo's owner clause rather than
    /// a second definition of "mine".
    #[test]
    fn messages_and_threads_both_apply_the_scope_rule() {
        let src = include_str!("agents.rs");
        for f in ["async fn messages_list(", "async fn threads_list("] {
            let needle = ["async fn ", f.trim_start_matches("async fn ")].concat();
            let body = src.split(needle.as_str()).last().expect("route");
            let body = &body[..body.find("\n}").unwrap()];
            let call = ["list_sees_everything(", "who.privileged"].concat();
            assert!(body.contains(&call), "{f} must apply list_sees_everything");
            assert!(body.contains("q.all"), "{f} must honour all=");
            assert!(body.contains("owner = Some(own.as_str())"), "{f} must fall back to owner scope");
        }
    }

    /// presence `all=true` is gated on privilege and served by `live_all`.
    #[test]
    fn presence_all_is_operator_only() {
        let src = include_str!("agents.rs");
        let needle = ["async fn ", "presence_list("].concat();
        let body = src.split(needle.as_str()).last().expect("presence route");
        let body = &body[..body.find("\n}").unwrap()];
        let gate = ["q.get(\"all\")", ".is_some_and"].concat();
        assert!(body.contains(&gate), "presence must read all=");
        let deny = ["if !who.priv", "ileged {"].concat();
        let all_at = body.find(&gate).unwrap();
        assert!(body[all_at..].find(&deny).unwrap() < body[all_at..].find("live_all").unwrap(), "403 check must precede live_all");
    }

    /// `/api/agents/whoami` is registered and answers from `caller(...)`.
    #[test]
    fn whoami_route_is_registered() {
        let src = include_str!("agents.rs");
        let route = ["\"/api/agents/", "whoami\", get(whoami)"].concat();
        assert!(src.contains(&route));
        let auth = include_str!("../auth.rs");
        let listed = ["\"/api/agents/", "whoami\""].concat();
        assert!(auth.contains(&listed), "whoami must be allow-listed in auth.rs");
    }

    /// Presence is scoped by the WIDE question (same owner), acting by the
    /// NARROW one (owns). A window sees its siblings and cannot become
    /// them. Pinned as source with the plant target named: swap
    /// `same_owner` for `owns` here and a session could no longer see its
    /// siblings; swap the other way in `owns` and it could act as them.
    #[test]
    fn presence_is_visible_to_siblings_but_not_actable() {
        // Needles assembled at runtime: this test module precedes the route
        // in the file, so a literal needle matches the test's own source
        // first and slices the wrong region (that is how the first version
        // of this test failed on correct code).
        let src = include_str!("agents.rs");
        let fn_needle = ["async fn ", "presence_list("].concat();
        let body = src.split(fn_needle.as_str()).last().expect("presence route");
        let body = &body[..body.find("\n}").unwrap()];
        let wide = ["same_owner", "(m, &owner)"].concat();
        let narrow = ["who.owns", "(&owner)"].concat();
        assert!(body.contains(&wide), "presence must be scoped by same_owner");
        assert!(!body.contains(&narrow), "presence must not require ownership — that would hide siblings");
        // …and the behaviour that pairs with it:
        let s1 = user_caller("owner/claude-s1");
        assert!(same_owner("owner/claude-s1", "owner"), "a session may list its account's presence");
        assert!(!s1.owns("owner/laptop"), "…and still may not act as a sibling");
    }

    /// Sessions must be RECORDED, not only remembered. Both doors open
    /// through the persistent `open(db, …)` and resolve through the
    /// persistent `from_headers(db, …)`; the in-process map is a cache.
    #[test]
    fn sessions_persist_through_both_doors() {
        for (name, src) in [("user door", include_str!("../mcp_external.rs")), ("operator door", include_str!("../mcp_local.rs"))] {
            let h = src.split("let req = &env.req;").nth(1).unwrap_or_else(|| panic!("{name}"));
            let h = &h[..h.find("\"tools/call\"").unwrap()];
            assert!(h.contains("mcp_session::from_headers(") && h.contains("db"), "{name}: resolve must go through the db-backed path");
            assert!(h.contains("mcp_session::open(") && h.contains("client_name"), "{name}: open must persist and carry the client's display name");
        }
    }

    /// A thread is a conversation a PERSON is in. Keying the seat to the
    /// connection would refuse the operator's second window from a thread
    /// their first window started.
    /// The owner boundary: wide on purpose, and a different question
    /// from `owns_name`.
    ///
    /// `owns_name` must stay NARROW or one session impersonates its
    /// siblings. This must stay WIDE or the operator's second window
    /// cannot talk to their own task. Both are prefix arithmetic on the
    /// same string; writing them once is the house failure mode.
    #[test]
    fn the_owner_boundary_is_wider_than_ownership() {
        // Every identity a person holds reaches that person's agents.
        assert!(same_owner("owner/laptop", "owner/claude-s1"));
        assert!(same_owner("owner", "owner/claude-s1"));
        assert!(same_owner("owner/laptop", "owner"));
        // …which `owns_name` refuses, and must:
        assert!(!crate::auth::owns_name("owner/laptop", "owner/claude-s1"));

        // Somebody else needs a trust entry.
        assert!(!same_owner("other/session", "owner/claude-s1"));
        assert!(!same_owner("other", "owner"));
        // A name that merely starts the same way is a different person.
        assert!(!same_owner("ownerx/s", "owner/s"));
        assert!(!same_owner("", "owner"));
    }

    /// A trust list is managed by the identity it protects, or by the
    /// account holding it — the NARROW question, not the wide one.
    ///
    /// The pairing matters: `same_owner` decides who may ADDRESS an
    /// agent, `owns_name` decides who may change the list of exceptions.
    /// Using the wide rule here would let one of a person's sessions
    /// widen another session's trust list, which is a quieter version of
    /// the sibling-impersonation problem.
    #[test]
    fn a_trust_list_is_managed_by_its_owner_not_its_peers() {
        let account = user_caller("owner");
        let s1 = user_caller("owner/claude-s1");
        let s2 = user_caller("owner/laptop");

        assert!(require_owns(&account, "owner/claude-s1").is_ok(), "the account manages its own");
        assert!(require_owns(&s1, "owner/claude-s1").is_ok(), "a session manages itself");
        assert!(
            require_owns(&s2, "owner/claude-s1").is_err(),
            "a session must not edit a sibling's trust list"
        );
        assert!(require_owns(&account, "other/session").is_err());
    }

    #[test]
    fn a_threads_seat_belongs_to_the_account() {
        assert_eq!(user_caller("alice/laptop").account().as_deref(), Some("alice"));
        assert_eq!(user_caller("alice").account().as_deref(), Some("alice"));
    }

    /// A node's own rule is unchanged by moving it onto the shared
    /// predicate: it owns agents UNDER its prefix and is not itself one.
    #[test]
    fn a_node_still_owns_only_what_is_under_it() {
        let n = caller(&None, &Some(Extension(ClusterNode("host8".into(), ClusterKind::Node))));
        assert!(n.owns("host8/agent"));
        assert!(!n.owns("host8"), "the node name itself is not one of its agents");
        assert!(!n.owns("other-node/agent"));
    }
}

// ═══════════════════════════════════════════════════════════════
// Agent roles — native Rust (ported from noomesh/agents/)
// ═══════════════════════════════════════════════════════════════

/// POST /api/agent/run — run one task under a role (or auto-classify).
async fn agent_run(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let prompt = body
        .get("prompt")
        .or_else(|| body.get("task"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let role = body.get("role").and_then(|v| v.as_str());
    // Callers may pass a conversation id; the Python path did not thread one,
    // so a per-call id keeps role runs out of the user's chat history.
    let cid = body
        .get("conversation_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("agent-run-{}", &uuid_hex()[..12]));

    match crate::agent_roles::run_agent(&state, prompt, role, &cid).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(e)).into_response(),
    }
}

/// POST /api/agents/collaborate — run one task through several roles.
async fn agents_collaborate(
    State(state): State<Arc<AppState>>,
    requester: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let prompt = body
        .get("prompt")
        .or_else(|| body.get("task"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let roles: Vec<String> = body
        .get("roles")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    // The person the tasks run as; an internal caller (the local MCP
    // door, a service) has none and the roles run unattended, in process.
    let owner = requester.as_ref().map(|r| r.0.sub.clone());
    // Block for the answer by default (the fan-out always did); `wait: 0`
    // returns the task ids at once and the caller reads the thread.
    let wait_secs = body
        .get("wait")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| std::env::var("NOO_COLLAB_WAIT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300))
        .min(3600);

    match crate::agent_roles::collaborate(&state, prompt, &roles, owner.as_deref(), wait_secs).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(e)).into_response(),
    }
}


// ── Agent messaging ─────────────────────────────────────────

use axum::extract::Query;
use axum::Extension;
use crate::auth::{ClusterNode, RequesterCtx};

/// Who is calling the messaging surface, reduced to what the handlers
/// need. Three shapes:
///
/// - a JWT: `sub` is the agent it may act as; operators and above are
///   privileged (see everything, send as anyone);
/// - a cluster token minted by one of the stack's own services
///   (`gateway`, `cli`, `trellion`, the MCP doors): privileged, no `sub`;
/// - a cluster token minted by a NODE: bound to `<node>/…` — it may send
///   as, read for, and register keys for agents on that node only.
///
/// Nothing else reaches these handlers (`require_any_auth`), and a caller
/// with neither context is treated as the least privileged shape.
struct Caller {
    sub: Option<String>,
    node: Option<String>,
    privileged: bool,
    /// For audit lines and `registered_by`.
    label: String,
    /// The software this call arrived through, derived from the credential
    /// class alone. See [`caller`] for the mapping.
    harness: String,
}

/// `harness` is never read from the request. It is a NAME FOR THE
/// CREDENTIAL CLASS, because that is the only thing about the calling
/// software the gateway can prove:
///
/// - `mcp-external:<consumer>` — the external MCP door, which signs the
///   consumer name into the JWT it mints (`mcp_external::mint_caller_jwt`);
/// - `internal:<actor>` — a controller-secret token: the local MCP door,
///   the worker, trellion, the CLI's self-calls;
/// - `node:<node>` — a node-agent's fleet-secret token;
/// - `api` — a plain user JWT. The CLI, the dashboard and a curl script all
///   present exactly the same credential, so naming one of them here would
///   reintroduce the very guess this row exists to remove.
///
/// The WS peer surface builds its own identity (`ws:<agent_id>`) in
/// `ws_agent.rs`; it does not come through here.
fn caller(requester: &Option<Extension<RequesterCtx>>, cluster: &Option<Extension<ClusterNode>>) -> Caller {
    if let Some(Extension(r)) = requester {
        return Caller {
            sub: Some(r.sub.clone()),
            node: None,
            privileged: r.role >= crate::auth::Role::Operator,
            label: r.sub.clone(),
            harness: r.harness.clone().unwrap_or_else(|| "api".into()),
        };
    }
    if let Some(Extension(c)) = cluster {
        if c.is_internal() {
            return Caller {
                sub: None,
                node: None,
                privileged: true,
                label: format!("cluster:{}", c.0),
                harness: format!("internal:{}", c.0),
            };
        }
        return Caller {
            sub: None,
            node: Some(c.0.clone()),
            privileged: false,
            label: format!("node:{}", c.0),
            harness: format!("node:{}", c.0),
        };
    }
    Caller { sub: None, node: None, privileged: false, label: "anonymous".into(), harness: "unknown".into() }
}

impl Caller {
    /// Is `agent` one this caller may act as or read for?
    ///
    /// a user credential now owns names under its own prefix
    /// the way a node always has, so `alice` may act as `alice/laptop`.
    /// The rule is [`crate::auth::owns_name`] for both, which is the point
    /// — one definition, so the node arm and the account arm cannot drift.
    ///
    /// **The asymmetry matters here more than anywhere**, because
    /// [`Self::may_read`] is built on this method: a CONNECTION credential
    /// owns only itself, so one of a person's sessions can neither act as
    /// nor read the mail of its siblings. That falls out of `owns_name`
    /// and is pinned there and in `sibling_sessions_are_strangers` below.
    fn owns(&self, agent: &str) -> bool {
        if self.privileged {
            return true;
        }
        if let Some(n) = &self.node {
            return crate::auth::owns_name(n, agent) && agent != n.as_str();
        }
        match self.sub.as_deref() {
            Some(sub) => crate::auth::owns_name(sub, agent),
            None => false,
        }
    }

    /// The ACCOUNT behind this caller, for the questions that are about a
    /// person rather than a session.
    ///
    /// Thread membership is the first of those: a thread is a
    /// conversation a PERSON is in, so their second window must be able to
    /// join it. Keying a seat to the connection would mean session 2 is
    /// refused from a thread session 1 started — same human, same account,
    /// told they are not a party to their own conversation.
    fn account(&self) -> Option<String> {
        self.sub.as_deref().map(|s| crate::auth::account_of(s).to_string())
    }

    /// The agent identity to act as: `from` when the caller may act as it,
    /// else the caller's own identity — a plain user cannot impersonate,
    /// a node cannot speak for another node.
    fn acting_agent(&self, wanted: Option<&str>) -> Result<String, AppError> {
        match wanted {
            Some(w) if self.owns(w) => Ok(w.to_string()),
            Some(w) => Err(AppError::Forbidden(format!("cannot act as '{w}' — you are '{}'", self.label))),
            None => match (&self.sub, &self.node) {
                (Some(s), _) => Ok(s.clone()),
                (None, Some(n)) => Ok(format!("{n}/agent")),
                // An internal service without `from`: the controller's own
                // identity for that service (`host8/mcp-server`).
                (None, None) if self.privileged => Ok(format!(
                    "{}/{}",
                    crate::agent_messages::controller_node(),
                    self.label.strip_prefix("cluster:").unwrap_or("service")
                )),
                _ => Err(AppError::BadRequest("from is required".into())),
            },
        }
    }

    /// Refuse a fan-out address from a caller that is not trusted
    /// fleet-wide. `to: "*"` reaches EVERY connected
    /// peer and makes the gateway open the body once per recipient, so it
    /// is an amplifier available to operators and internal services only;
    /// a node-bound token or a user-tier JWT addresses agents by name.
    fn check_broadcast(&self, to: &str) -> Result<(), AppError> {
        if matches!(to, "*" | "broadcast") && !self.privileged {
            return Err(AppError::Forbidden(format!(
                "broadcast is operator-only — '{}' may address one agent or a thread by name",
                self.label
            )));
        }
        Ok(())
    }

    /// Can this caller read message `m` (a row as the API returns it)?
    ///
    /// Plus the FAN-OUT rule (the account-addressed residue,
    /// decided here rather than by accident): a message addressed to a
    /// bare ACCOUNT is readable by every connection under it. "To me"
    /// means every window I have open. Without this, the moment the MCP
    /// door started minting connections, mail addressed to `owner` would
    /// have become invisible to all of `owner`'s sessions — because a
    /// connection does not OWN its account, and must not.
    ///
    /// Deliberately one-directional: mail addressed to one CONNECTION is
    /// that connection's alone — the account may read it (it owns every
    /// connection), a sibling may not.
    fn may_read(&self, m: &Value) -> bool {
        let (from, to) = (m["from"].as_str().unwrap_or(""), m["to"].as_str().unwrap_or(""));
        if self.owns(from) || self.owns(to) {
            return true;
        }
        match self.sub.as_deref() {
            Some(sub) => !to.is_empty() && to == crate::auth::account_of(sub) && sub != to,
            None => false,
        }
    }
}

/// May `from` address `to`, before consulting any stored exception?
/// (the default.)
///
/// **The boundary is the OWNER, not the door.** Every identity a person
/// holds may address that person's agents, through any door — steering an
/// internal node harness from an external MCP client is the feature, not
/// the threat. An earlier draft of the proposal had internal agents deny
/// external senders by default and the operator rejected it, correctly.
///
/// So what is refused is an **unattributed or foreign** sender, not a
/// distant one. A credential belonging to somebody else needs a trust
/// entry (`repo::agent_messages::is_trusted`).
///
/// Pure, and account-to-account on purpose: this is the question "are we
/// the same person", which is wider than `owns_name`'s "is this name
/// mine". Both are prefix arithmetic on the same string and they must not
/// be written once — `owns_name` must stay narrow or one session
/// impersonates its siblings, and this must stay wide or the operator's
/// second window cannot talk to their own task.
///
/// Team is the next widening and lands HERE, as a wider comparison
/// against the same two accounts.
/// Whether a seat may post into a thread, given what the lookup said.
/// `Some(false)` is the only refusal: the thread exists and the seat is not in
/// it. `None` (no such thread) admits, because claiming an unused thread id is
/// legitimate. A database ERROR fails closed (500) and never admits.
fn seat_in_thread<E: std::fmt::Display>(found: Result<Option<bool>, E>) -> Result<bool, AppError> {
    match found {
        Ok(Some(false)) => Ok(false),
        Ok(_) => Ok(true),
        Err(e) => Err(AppError::Internal(format!("thread membership lookup failed: {e}"))),
    }
}

/// Ack is the recipient's act: the caller must own the address the mail was sent to.
fn may_ack(who: &Caller, to: &str) -> bool {
    who.owns(to)
}

pub(crate) fn same_owner(from: &str, to: &str) -> bool {
    let (a, b) = (crate::auth::account_of(from), crate::auth::account_of(to));
    !a.is_empty() && a == b
}

/// GET /api/agents/presence?owner=<account> — the live MCP sessions under
/// an account.
///
/// Scoped by `same_owner`, not `owns_name`: a window may SEE its siblings
/// — that is discovery, "which of me is alive so I can address it" — while
/// still being unable to act as them, which `owns_name` keeps refusing.
/// Two questions, two answers. An operator may list anyone; anyone else
/// lists their own account, and asking for another's is refused rather
/// than emptied, so "nobody is online" never means "you may not look".
///
/// Everything returned is ADVERTISEMENT (the record says what this
/// window is, never what it may do), and `display_name` is display-only.
async fn presence_list(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    // `all=true`: every account's live sessions. Operator-only, refused
    // (not narrowed) for anyone else, like the message and thread lists.
    if q.get("all").is_some_and(|v| v == "true" || v == "1") {
        if !who.privileged {
            return Err(AppError::Forbidden("all=true is operator-only — omit it to list your own account's presence".into()));
        }
        let sessions = crate::mcp_session::live_all(&state.db).await?;
        return Ok(Json(json!({ "owner": null, "all": true, "sessions": sessions, "idle_ttl_secs": crate::mcp_session::IDLE_TTL.as_secs() })));
    }
    let mine = who.account();
    let owner = q.get("owner").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).or_else(|| mine.clone());
    let Some(owner) = owner else {
        return Err(AppError::BadRequest("owner is required for a caller with no account of its own".into()));
    };
    if !who.privileged && !mine.as_deref().is_some_and(|m| same_owner(m, &owner)) {
        return Err(AppError::Forbidden(format!(
            "'{}' may list presence for its own account, not for '{owner}'",
            who.label
        )));
    }
    let sessions = crate::mcp_session::live_for(&state.db, &owner).await?;
    Ok(Json(json!({ "owner": owner, "sessions": sessions, "idle_ttl_secs": crate::mcp_session::IDLE_TTL.as_secs() })))
}

/// GET /api/agents/whoami — the acting agent name of this session (the
/// address other sessions use to message it), its account, the harness the
/// credential arrived through, and whether it is privileged. `name` is null
/// only when no identity can be derived at all (an anonymous caller); a
/// service token reports its controller-side service identity.
async fn whoami(
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    let name = who.acting_agent(None).ok();
    let account = name.as_deref().map(|n| crate::auth::account_of(n).to_string());
    Ok(Json(json!({
        "name": name,
        "account": account,
        "harness": who.harness,
        "privileged": who.privileged,
    })))
}

#[derive(Deserialize)]
struct NameReq {
    /// The session half of the new name; the type half stays the client's.
    name: String,
}

/// POST /api/agents/name — give THIS MCP session a name its person chose:
/// `{"name": "general"}` turns `owner/claude-x7k2qa` into
/// `owner/claude-general`, the address other sessions then use. Only a
/// session can be renamed: a bare account, a node or a service token has
/// no session label to change (400). A name another live session of the
/// account already holds is joined, not refused — a name is a mailbox
/// (`mcp_session::rename`) — and `shared_with` says how many were there.
async fn agent_name(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Json(req): Json<NameReq>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    let Some(sub) = who.sub.as_deref() else {
        return Err(AppError::BadRequest(format!("'{}' is not an MCP session; only a session has a name to set", who.label)));
    };
    let Some((account, old)) = sub.split_once(crate::auth::CONNECTION_SEP) else {
        return Err(AppError::BadRequest(format!(
            "'{sub}' is the account itself, not a session — call this through an MCP door session"
        )));
    };
    let (label, shared_with) = crate::mcp_session::rename(&state.db, account, old, &req.name)
        .await
        .map_err(AppError::BadRequest)?;
    let name = format!("{account}{}{label}", crate::auth::CONNECTION_SEP);
    Ok(Json(json!({ "name": name, "account": account, "previous": sub, "shared_with": shared_with })))
}

#[derive(Deserialize)]
struct TrustReq {
    /// The agent whose list this is. The caller must own it.
    agent: String,
    /// An account or a connection that may address `agent`.
    allowed: String,
    #[serde(default)]
    note: Option<String>,
}

/// The caller must OWN the agent whose trust list it is reading or
/// changing — `owns_name`, the narrow question, not `same_owner`.
///
/// Narrow on purpose: a trust list decides who may put instructions in
/// front of an agent, so one of a person's sessions must not be able to
/// widen another's. The person themselves can, from an account
/// credential, which owns every connection under it.
fn require_owns(who: &Caller, agent: &str) -> Result<(), AppError> {
    if who.owns(agent) {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "'{}' does not own '{agent}' — a trust list is managed by the identity it protects, \
         or by the account that holds it",
        who.label
    )))
}

/// GET /api/agents/trust?agent=… — the exceptions for one agent.
///
/// Only the exceptions. The default — every identity the owner holds —
/// is a rule rather than rows, so an empty list means "my owner's
/// identities and nobody else", not "nobody".
async fn trust_list(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    let agent = q.get("agent").map(String::as_str).unwrap_or("").trim();
    if agent.is_empty() {
        return Err(AppError::BadRequest("agent is required".into()));
    }
    require_owns(&who, agent)?;
    let rows: Vec<(String, Option<String>, chrono::DateTime<chrono::Utc>, Option<String>)> =
        sqlx::query_as(
            "SELECT allowed, note, created_at, created_by FROM noo_agent_trust \
             WHERE agent = $1 ORDER BY created_at",
        )
        .bind(agent)
        .fetch_all(&state.db)
        .await?;
    Ok(Json(json!({
        "agent": agent,
        "owner_default": crate::auth::account_of(agent),
        "trusted": rows.iter().map(|(a, n, c, by)| json!({
            "allowed": a, "note": n, "created_at": c, "created_by": by,
        })).collect::<Vec<_>>(),
    })))
}

/// POST /api/agents/trust — let an identity outside the owner address this agent.
async fn trust_add(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    actor: Option<Extension<crate::auth::AuthActor>>,
    Json(req): Json<TrustReq>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    let (agent, allowed) = (req.agent.trim(), req.allowed.trim());
    require_owns(&who, agent)?;
    crate::agent_messages::check_id("allowed", allowed).map_err(AppError::BadRequest)?;
    // Refusing a no-op entry rather than storing it: an entry for an
    // identity the owner already holds would sit in the list implying it
    // is load-bearing, and be deleted one day by someone who reasonably
    // concluded it was.
    if same_owner(allowed, agent) {
        return Err(AppError::BadRequest(format!(
            "'{allowed}' is already covered — an agent accepts every identity its owner holds, \
             so this entry would grant nothing and imply it did"
        )));
    }
    sqlx::query(
        "INSERT INTO noo_agent_trust (agent, allowed, note, created_by) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (agent, allowed) DO UPDATE SET note = EXCLUDED.note",
    )
    .bind(agent)
    .bind(allowed)
    .bind(&req.note)
    .bind(actor.as_ref().map(|Extension(a)| a.0.clone()))
    .execute(&state.db)
    .await?;
    tracing::info!(agent, allowed, by = %who.label, "agent_trust_added");
    Ok(Json(json!({ "agent": agent, "allowed": allowed, "trusted": true })))
}

/// POST /api/agents/trust/remove — withdraw one entry.
///
/// A POST rather than a DELETE with path params: both names may contain
/// `/`, and a path-encoded identity is a decoding bug waiting to become
/// an authorization bug.
async fn trust_remove(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Json(req): Json<TrustReq>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    let (agent, allowed) = (req.agent.trim(), req.allowed.trim());
    require_owns(&who, agent)?;
    let n = sqlx::query("DELETE FROM noo_agent_trust WHERE agent = $1 AND allowed = $2")
        .bind(agent)
        .bind(allowed)
        .execute(&state.db)
        .await?
        .rows_affected();
    tracing::info!(agent, allowed, removed = n, by = %who.label, "agent_trust_removed");
    Ok(Json(json!({ "agent": agent, "allowed": allowed, "removed": n })))
}

#[derive(Deserialize)]
struct SendReq {
    #[serde(default)]
    from: Option<String>,
    to: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    thread_id: Option<String>,
    #[serde(default)]
    refs: Vec<String>,
    /// Phase 2: which agent instance is speaking (user + node are taken
    /// from the credential and this controller).
    #[serde(default)]
    agent: Option<String>,
    /// The AUTHOR's own Ed25519 signature over
    /// `agent_crypto::author_signing_input`
    /// closing.
    ///
    /// Optional, and additive on purpose: until every client signs,
    /// requiring it would silence the mesh. What it changes is what a
    /// receiver can conclude. Without it, "signed" means the CONTROLLER
    /// signed — a compromised controller could mint a message from any
    /// agent and it would verify. With it, the named agent's own key
    /// signed the content, which is the part a compromised controller
    /// cannot forge.
    ///
    /// Verified when present and REFUSED when it does not verify. Never
    /// accepted-but-ignored: a signature that is checked only sometimes
    /// is worth less than no signature, because it invites a receiver to
    /// rely on it.
    #[serde(default)]
    author_sig: Option<String>,
    /// What the caller says its software is. Recorded as
    /// `from_id.harness_claimed`, a hint — `from_id.harness` is derived
    /// from the credential class.
    #[serde(default, alias = "harness_claimed")]
    harness: Option<String>,
}

/// POST /api/agents/messages — send (publish to the stream; the recorder
/// persists it). Returns the envelope as sent.
async fn messages_send(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Json(req): Json<SendReq>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    who.check_broadcast(&req.to)?;
    let from = who.acting_agent(req.from.as_deref())?;
    let body = match (req.body, req.text) {
        (Some(b), _) => b,
        (None, Some(t)) => json!({ "text": t }),
        (None, None) => return Err(AppError::BadRequest("body or text is required".into())),
    };
    // Posting into an existing thread needs a seat in it.
    if let Some(t) = req.thread_id.as_deref() {
        if !who.privileged {
            // Checked for the connection AND for the account behind it
            // A thread is a conversation a person is in;
            // once sessions are distinct identities, a seat held by
            // `alice/claude-s1` must still admit `alice/laptop`, or the
            // operator's second window cannot join their own thread.
            let mut seats: Vec<String> = vec![from.clone()];
            if let Some(acct) = who.account() {
                if acct != from {
                    seats.push(acct);
                }
            }
            let mut party = false;
            for seat in &seats {
                if seat_in_thread(crate::repo::agent_messages::is_party(&state.db, t, seat).await)? {
                    party = true;
                    break;
                }
            }
            if !party {
                return Err(AppError::Forbidden(format!(
                    "'{from}' is not a party to thread '{t}'"
                )));
            }
        }
    }
    // Two refusals, both of which used to be silent
    // acceptances.
    //
    // Ordered existence-then-permission on purpose: "there is no such
    // agent" and "you may not address it" are different answers and a
    // sender can act on the first. It also means the trust lookup only
    // runs for a recipient that could receive.
    if !who.privileged {
        let to_account = crate::auth::account_of(&req.to);
        // `noo_node_config`, not a guessed `noo_nodes` — the first draft
        // of this query named a table that does not exist, and paired
        // with `unwrap_or(false)` it would have refused EVERY message
        // while looking like a working trust check. The error is
        // propagated rather than swallowed for that reason: a database
        // that cannot answer "does this recipient exist" must surface as
        // a 500, not as "no such recipient".
        let known: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM noo_users WHERE username = $1) \
             OR EXISTS (SELECT 1 FROM noo_node_config WHERE node_id = $1)",
        )
        .bind(to_account)
        .fetch_one(&state.db)
        .await?;
        if !known {
            // Previously accepted and stored. A message to a name nobody
            // holds sat in the table forever and the sender was told
            // "sent" — the silent-success shape this repo has spent a
            // week removing.
            return Err(AppError::NotFound(format!(
                "no such recipient '{}' — '{to_account}' is not an account or a node",
                req.to
            )));
        }
        if !same_owner(&from, &req.to)
            && !crate::repo::agent_messages::is_trusted(&state.db, &req.to, &from).await?
        {
            return Err(AppError::Forbidden(format!(
                "'{from}' may not address '{}' — an agent accepts identities its own owner \
                 holds, and others only by a trust entry",
                req.to
            )));
        }
    }

    // Phase D. An author signature is verified against the key the agent
    // REGISTERED, not against anything in this request — otherwise it
    // would be a claim dressed as proof.
    let author_signed = match req.author_sig.as_deref() {
        None => false,
        Some(sig) => {
            let Some((_, verify_key)) =
                crate::agent_crypto::registered_keys(&state.js, &from).await
            else {
                return Err(AppError::BadRequest(format!(
                    "'{from}' supplied an author signature but has no registered key — \
                     register one at PUT /api/agents/keys/{from}"
                )));
            };
            let input = crate::agent_crypto::author_signing_input(
                &from,
                &req.to,
                req.kind.as_deref().unwrap_or("message"),
                req.thread_id.as_deref().unwrap_or(""),
                &body,
            );
            if !crate::agent_crypto::verify(&verify_key, &input, sig) {
                return Err(AppError::Forbidden(
                    "author signature does not verify under the agent's registered key".into(),
                ));
            }
            true
        }
    };

    let user = who.sub.clone();
    // A node-bound caller's messages are attributed to that node, not the
    // controller that relayed them.
    let node = who.node.clone().unwrap_or_else(crate::agent_messages::controller_node);
    // `harness` comes from the credential class, never the body — a sender
    // used to be able to label itself `claude-code` and have the CLI print
    // it in the same column as the server-derived user and node. Whatever
    // the caller asked for rides along as a clearly-named claim.
    let identity = crate::agent_messages::Identity::new(
        user.as_deref(),
        Some(&node),
        Some(req.agent.as_deref().unwrap_or(&from)),
        Some(&who.harness),
    )
    .with_claimed_harness(req.harness.as_deref());
    let env = crate::agent_messages::Envelope::new(
        &from,
        &req.to,
        req.kind.as_deref().unwrap_or("message"),
        body,
        req.thread_id.as_deref(),
        req.refs,
    )
    .with_from(identity);
    let sent = crate::agent_messages::publish(&state.js, &env)
        .await
        .map_err(|e| AppError::Internal(format!("send failed: {e}")))?;
    // Echo what the caller sent (plaintext) plus how it travelled.
    Ok(Json(json!({
        "sent": true,
        "message": env,
        "enc": sent.enc,
        // `signed` has always meant "the controller signed this". Kept,
        // because changing what an existing field means is worse than
        // adding one.
        "signed": sent.sig.is_some(),
        // What a compromised controller could not have produced. A
        // receiver that cares about authorship reads THIS.
        "author_signed": author_signed,
    })))
}

#[derive(Deserialize, Default)]
struct ListQuery {
    agent: Option<String>,
    from: Option<String>,
    to: Option<String>,
    thread: Option<String>,
    kind: Option<String>,
    since: Option<String>,
    user: Option<String>,
    node: Option<String>,
    harness: Option<String>,
    #[serde(default)]
    unread: bool,
    /// Operators only: list every session's mail, not just the caller's own.
    #[serde(default)]
    all: bool,
    limit: Option<i64>,
}

/// Does this list call see the whole system (`true`) or only the caller's
/// own mail (`false`)?
///
/// Anything with an acting identity (`sub`) is scoped to its own names by
/// default, operator role or not: an operator's window is a person's
/// session with its own inbox, not a firehose. Widening is explicit
/// (`all=true`) and only a privileged caller may ask — anyone else is
/// refused rather than silently narrowed. The shared cluster token (the
/// stack's own services) has no `sub` and keeps seeing everything.
fn list_sees_everything(privileged: bool, has_sub: bool, all: bool) -> Result<bool, &'static str> {
    if all && !privileged {
        return Err("all=true is operator-only — omit it to list your own messages");
    }
    Ok(privileged && (all || !has_sub))
}

/// **Delivery is to a CONNECTION, not to an owner** — decided by the
/// operator 2026-09-13, after review raised it as ambiguous.
///
/// A message goes to the specific session, and a reply goes back to the
/// session that sent the original. That falls out of the identity work
/// rather than needing machinery: once `from` carries the connection
/// (`owner/laptop` rather than `owner`), replying is addressing
/// `from`, and it lands in the one window that asked. Three live sessions
/// of one person hold three inboxes, three unread counts and three threads
/// — which is the point, and why presence and read state key on the
/// connection while history and usage key on the account.
///
/// The residue: a message addressed to a bare ACCOUNT with several live
/// connections. Addressing the account is now the unusual case rather than
/// the normal one, but it stays legal, and **whoever writes the presence
/// query in phase C must choose** — fan out to every live connection, or
/// let the first reader claim it. Fan out is the better default for a
/// person (the audience is "me", wherever I am looking); first-claim
/// suits a worker pool. Unresolved on purpose; resolve it deliberately,
/// because the alternative is learning the answer from a message one
/// window saw and another did not.
const _ACCOUNT_ADDRESSED_DELIVERY_IS_UNDECIDED: () = ();

/// GET /api/agents/archive — the agent-mail archive files (operator-only).
async fn archive_list(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    if !who.privileged {
        return Err(AppError::Forbidden("the agent-mail archive is operator-only".into()));
    }
    let dir = crate::agent_mail_archive::configured_dir(&state.db).await;
    let d = dir.clone();
    let files = tokio::task::spawn_blocking(move || crate::agent_mail_archive::list(&d))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(AppError::Internal)?;
    let total: u64 = files.iter().map(|f| f.rows).sum();
    Ok(Json(json!({
        "dir": dir.display().to_string(),
        "files": files.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
        "total_rows": total,
    })))
}

#[derive(Deserialize)]
struct ArchiveExportQuery {
    #[serde(default)]
    decrypt: bool,
}

/// GET /api/agents/archive/{month} — one month's rows (`YYYY-MM` or the file
/// name). Bodies stay sealed unless `?decrypt=true`, which needs an operator
/// AND the review key and is audited before any plaintext is produced.
async fn archive_export(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(month): Path<String>,
    Query(q): Query<ArchiveExportQuery>,
) -> AppResult {
    use crate::agent_mail_archive::ExportError as E;
    let who = caller(&requester, &cluster);
    let dir = crate::agent_mail_archive::configured_dir(&state.db).await;
    let keys = if q.decrypt { crate::agent_crypto::controller_keys() } else { None };
    crate::agent_mail_archive::export(&state.db, &dir, who.privileged, &who.label, &month, keys, q.decrypt)
        .await
        .map(Json)
        .map_err(|e| match e {
            E::Forbidden(m) => AppError::Forbidden(m),
            E::BadRequest(m) => AppError::BadRequest(m),
            E::NotFound(m) => AppError::NotFound(m),
            E::NoKey(m) => AppError::Unavailable(m),
            E::Internal(m) => AppError::Internal(m),
        })
}

/// GET /api/agents/messages — list, newest first. Non-privileged callers
/// see only messages they sent or received.
async fn messages_list(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(q): Query<ListQuery>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    // Whose unread this is: the acting identity, so each window of a
    // person has its own read state. A privileged caller with no identity
    // (the shared cluster token) has none, and falls back to the
    // whole-message `read_at`.
    let reader = who.acting_agent(None).ok();
    let own;
    let mut owner: Option<&str> = None;
    let widen = list_sees_everything(who.privileged, who.sub.is_some(), q.all)
        .map_err(|m| AppError::Forbidden(m.into()))?;
    // An explicit `agent=` from a privileged caller is already a deliberate
    // choice and keeps working as before.
    let (agent, node_prefix) = if who.privileged && (widen || q.agent.is_some()) {
        (q.agent.as_deref(), None)
    } else if let Some(n) = &who.node {
        // A node sees its own agents' traffic; a narrower `agent` is fine
        // when it is one of them.
        match q.agent.as_deref() {
            Some(a) if who.owns(a) => (Some(a), None),
            Some(a) => return Err(AppError::Forbidden(format!("'{a}' is not an agent on node '{n}'"))),
            None => (None, Some(n.as_str())),
        }
    } else {
        // "You" is everything the credential owns (`auth::owns_name`): an
        // account reads its connections' mail too, a connection only its
        // own — the same rule `may_read` applies to one message, and the
        // one the loop's native inbox uses.
        own = who.sub.clone().unwrap_or_default();
        owner = Some(own.as_str());
        (None, None)
    };
    let since = q
        .since
        .as_deref()
        .map(|s| chrono::DateTime::parse_from_rfc3339(s).map(|t| t.with_timezone(&chrono::Utc)))
        .transpose()
        .map_err(|e| AppError::BadRequest(format!("since: {e}")))?;
    let rows = crate::repo::agent_messages::list(
        &state.db,
        &crate::repo::agent_messages::Filter {
            agent,
            owner,
            node_prefix,
            from: q.from.as_deref(),
            to: q.to.as_deref(),
            thread: q.thread.as_deref(),
            kind: q.kind.as_deref(),
            user: q.user.as_deref(),
            node: q.node.as_deref(),
            harness: q.harness.as_deref(),
            since,
            unread_only: q.unread,
            // Unread is per reader: this caller's own acks
            // decide it, whatever a sibling window has done.
            reader: reader.as_deref(),
            limit: q.limit.unwrap_or(50),
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!({ "messages": rows, "count": rows.len() })))
}

async fn messages_get(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(id): Path<String>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    let Some(m) = crate::repo::agent_messages::get(&state.db, &id)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
    else {
        return Err(AppError::NotFound("message not found".into()));
    };
    if !who.may_read(&m) {
        return Err(AppError::Forbidden("not a party to this message".into()));
    }
    Ok(Json(m))
}

async fn messages_ack(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(id): Path<String>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    if !who.privileged {
        let Some(m) = crate::repo::agent_messages::get(&state.db, &id)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
        else {
            return Err(AppError::NotFound("message not found".into()));
        };
        if !may_ack(&who, m["to"].as_str().unwrap_or("")) {
            return Err(AppError::Forbidden("only the recipient can ack".into()));
        }
    }
    // The reader is the ACTING identity — a connection acks as itself, a
    // bare-account CLI as the account, a node as its agent. A privileged
    // caller with no identity of its own (the shared cluster token) acks
    // as the recipient, which is the only meaning "ack" can have for it.
    let reader = match who.acting_agent(None) {
        Ok(a) => a,
        Err(_) => crate::repo::agent_messages::get(&state.db, &id)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .and_then(|m| m["to"].as_str().map(str::to_string))
            .ok_or_else(|| AppError::NotFound("message not found".into()))?,
    };
    let ok = crate::repo::agent_messages::mark_read(&state.db, &id, &reader)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !ok {
        return Err(AppError::NotFound("message not found".into()));
    }
    Ok(Json(json!({ "acked": true, "id": id })))
}

#[derive(Deserialize, Default)]
struct ThreadsQuery {
    agent: Option<String>,
    /// Operators only: every thread, not just the caller's own.
    #[serde(default)]
    all: bool,
    limit: Option<i64>,
}

/// GET /api/agents/threads — threads derived from the record, newest first.
async fn threads_list(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(q): Query<ThreadsQuery>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    let widen = list_sees_everything(who.privileged, who.sub.is_some(), q.all)
        .map_err(|m| AppError::Forbidden(m.into()))?;
    let own;
    let mut owner: Option<&str> = None;
    let agent = if who.privileged && (widen || q.agent.is_some()) {
        q.agent.as_deref()
    } else if who.node.is_some() {
        // Threads are per agent; a node names which of its agents.
        match q.agent.as_deref() {
            Some(a) if who.owns(a) => Some(a),
            Some(a) => return Err(AppError::Forbidden(format!("'{a}' is not an agent on this node"))),
            None => return Err(AppError::BadRequest("agent is required (one of this node's agents)".into())),
        }
    } else {
        // The account rule (`auth::owns_name`), via the repo's one owner
        // clause — the same "mine" `messages_list` uses.
        own = who.sub.clone().unwrap_or_default();
        owner = Some(own.as_str());
        None
    };
    let rows = crate::repo::agent_messages::threads(&state.db, agent, owner, q.limit.unwrap_or(50))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!({ "threads": rows, "count": rows.len() })))
}


// ── Key registry ────────────────────────────────────

/// GET /api/agents/keys/{agent} — the agent's registered public keys.
async fn keys_get(State(state): State<Arc<AppState>>, Path(agent): Path<String>) -> AppResult {
    let Some(kv) = state.js.get_key_value(crate::agent_crypto::KEYS_BUCKET).await.ok() else {
        return Err(AppError::Internal("key registry unavailable".into()));
    };
    let raw = kv
        .get(crate::agent_messages::subject_token(&agent))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    match raw {
        Some(b) => Ok(Json(serde_json::from_slice(&b).unwrap_or(Value::Null))),
        None => Err(AppError::NotFound(format!("no keys registered for '{agent}'"))),
    }
}

/// PUT /api/agents/keys/{agent} — register (replace) an agent's public keys.
/// The caller must BE that agent (its subject), its node, or an operator;
/// the record must be self-signed, and replacing a different key needs
/// the old key's signature unless the caller is an operator (audited).
async fn keys_put(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(agent): Path<String>,
    Json(record): Json<Value>,
) -> AppResult {
    let who = caller(&requester, &cluster);
    crate::agent_messages::check_id("agent", &agent).map_err(AppError::BadRequest)?;
    let _ = who.acting_agent(Some(&agent))?;
    crate::agent_crypto::register_keys(&state.js, &agent, &record, &who.label, who.privileged)
        .await
        .map_err(AppError::BadRequest)?;
    if who.privileged {
        crate::routes::core::audit_event(
            &state.db,
            "agent_key_registered",
            "info",
            &who.label,
            &agent,
            "ok",
            json!({ "agent": agent, "by": who.label, "privileged": true }),
        )
        .await;
    }
    Ok(Json(json!({ "registered": true, "agent": agent })))
}

/// GET /api/agents/keys/review — the controller's public sealing + signing
/// keys, so a participant can wrap to the review key itself and verify
/// gateway signatures. Public: they are public keys.
async fn keys_review() -> AppResult {
    match crate::agent_crypto::controller_keys() {
        Some(k) => Ok(Json(k.public_record())),
        None => Err(AppError::NotFound("no review key configured on this controller".into())),
    }
}
