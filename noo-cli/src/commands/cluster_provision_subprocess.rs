// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC


// This file is `include!`d into `cluster_provision.rs` — it shares that
// module's imports (Command, Stdio, Value, json, fail, ExitCode, repo_root,
// fetch_node, online_nodes, spawn_inherited, base64_std,
// plain_agent, env_value, read_hidden, fmt_g, get_json, get_json_opt,
// post_json_try, Globals, Unhandled, …). Kept separate only to keep each
// file navigable. No `mod`/re-`use` of already-imported items here.

// ════════════════════════════════════════════════════════════════════
//  Shared subprocess/network helpers
// ════════════════════════════════════════════════════════════════════

/// Controller LAN IP via the UDP-connect trick (no packet sent).
fn detect_lan_ip() -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    let ip = s.local_addr().ok()?.ip().to_string();
    if ip == "0.0.0.0" { None } else { Some(ip) }
}








// ════════════════════════════════════════════════════════════════════
//  sync-images — controller export + agent pull over the artifact rail
//  
// ════════════════════════════════════════════════════════════════════

fn container_name_for_image(image: &str) -> Option<&'static str> {
    let short = image.rsplit('/').next().unwrap_or(image).split(':').next().unwrap_or(image);
    match short {
        "node-agent" => Some("noo-node-agent"),
        "vllm-openai" => Some("noo-vllm"),
        "llamacpp" => Some("noo-llamacpp"),
        "ollama" => Some("noo-ollama"),
        _ => None,
    }
}



/// Where the controller's GGUF weights live on the host — nginx serves it as
/// `/gguf/`, the gateway manifests it as kind=gguf AND kind=modelfile. The
/// two share a directory because `ollama create` resolves a Modelfile's
/// `FROM ./<file>` relative to the Modelfile: separated, neither is usable.
/// `noo cluster import-model <node> <name> [--place] [--role r] [-b backend]`
///
/// The second half of `ship-model` without the first: the GGUF and its
/// Modelfile are ALREADY in the controller's store (published by an earlier
/// ship, or staged by hand — the harrier embedder ships as an OCI artifact
/// and never goes through an HF conversion), and the node should import
/// them into its ollama. Same one-name contract as the pull kind: the agent
/// fetches `<name>.Modelfile`, reads the weight it names, fetches that,
/// verifies both digests, and runs `ollama create`.
pub fn cluster_import_model(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positional: Vec<String> = Vec::new();
    let mut place = false;
    let mut role: Option<String> = None;
    let mut backend = "ollama".to_string();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--place" => place = true,
            "--role" => role = Some(iter.next().ok_or(Unhandled)?.clone()),
            "-b" | "--backend" => backend = iter.next().ok_or(Unhandled)?.clone(),
            t if t.starts_with('-') => return Err(Unhandled),
            t => positional.push(t.to_string()),
        }
    }
    let [node, name] = positional.as_slice() else { return Err(Unhandled) };
    if let Some(r) = &role {
        if !matches!(r.as_str(), "chat" | "embed" | "rerank") {
            fail(g.json, ExitCode::Usage, "bad_role", "--role must be chat, embed or rerank", None);
        }
    }
    // The store must hold the pair the agent will ask for, or the import
    // fails one hop later with a less useful message.
    let store = gguf_store_dir();
    // `ollama:<tag>` (or an unambiguous bare tag) names a registry tag that
    // `noo models fetch ollama:<tag>` staged; the node resolves the same tag
    // to the same pair and imports it through the verified path. A tag that
    // is not staged is refused here, naming the fetch command.
    let (name, mf, staged) = match super::ollama_stage::resolve_import_target(name, &store) {
        Ok(super::ollama_stage::ImportTarget::Staged(r)) => {
            let mf = store.join(format!("{}.Modelfile", r.stem()));
            (r.short(), mf, true)
        }
        Ok(super::ollama_stage::ImportTarget::Plain(n)) => {
            let mf = store.join(format!("{n}.Modelfile"));
            (n, mf, false)
        }
        Err(e) => fail(g.json, ExitCode::Generic, "not_staged", &e,
            Some("`noo models fetch ollama:<tag>` stages a registry tag in the controller store; `noo cluster ship-model <hf_id> <node>` publishes a converted model")),
    };
    let name = name.as_str();
    if !staged && !mf.is_file() {
        // Not published yet: a model that ships as an OCI artifact under the
        // release namespace (<prefix>/<name>:v1 — harrier does) can be
        // staged from the registry the stack already logs into. On
        // 2026-09-09 this was done by hand with docker create + docker cp;
        // the verb does it now, and says so.
        match stage_artifact_into_store(name, &store) {
            Ok(files) => { if !g.json { ui::done(&format!("staged {} into {} from the registry artifact", files.join(" + "), store.display())); } }
            Err(e) => fail(g.json, ExitCode::Generic, "no_modelfile",
                &format!("{} is not in the controller store ({}) and could not be staged from the registry: {e}", mf.display(), store.display()),
                Some("publish the pair first: `noo cluster ship-model <hf_id> <node>` converts and publishes; a converted model is two files, <name>.Modelfile and the weight its FROM line names")),
        }
    }
    let Ok(body) = std::fs::read_to_string(&mf) else {
        fail(g.json, ExitCode::Generic, "no_modelfile",
            &format!("{} is not readable", mf.display()), None);
    };
    let weight = body.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("FROM ").map(|w| w.trim().trim_start_matches("./").to_string()))
        .unwrap_or_default();
    if weight.is_empty() || !weight.to_ascii_lowercase().ends_with(".gguf") || weight.contains('/') {
        fail(g.json, ExitCode::Generic, "bad_modelfile",
            &format!("{} must start with `FROM <bare>.gguf` — the agent imports a converted weight, never a registry pull", mf.display()), None);
    }
    if !store.join(&weight).is_file() {
        fail(g.json, ExitCode::Generic, "no_weight",
            &format!("{weight} (named by {}) is not in the controller store", mf.display()), None);
    }
    if !g.json {
        println!("{}", ui::phase("Create"));
        ui::step(&format!("{node}'s agent is fetching {name}.Modelfile + {weight} and running ollama create {name}"));
    }
    match post_json_try(
        g,
        &format!("/api/cluster/nodes/{}/pull", super::urlencode(node)),
        &json!({ "kind": "ollama-model", "name": name }),
        true,
        3600,
    ) {
        Ok(resp) => {
            if !g.json {
                let via = resp["via"].as_str().unwrap_or("?");
                ui::done(&format!("{name} created on {node} (via the {via} ollama)"));
            }
        }
        Err(e) => fail(g.json, ExitCode::Generic, "create_failed",
            &format!("the node could not import the model: {e}"), None),
    }
    if place {
        let mut pb = json!({"model": name, "desired_state": "running", "tls": false});
        if let Some(r) = &role { pb["role"] = json!(r); }
        match crate::http::put_json_try(
            g,
            &format!("/api/cluster/nodes/{}/placements/{}", super::urlencode(node), super::urlencode(&backend)),
            &pb, true, 15,
        ) {
            Ok(_) => {
                if !g.json {
                    ui::close_done(&format!("{name} imported and placed on {node} as {backend}{}",
                        role.as_deref().map(|r| format!(" (role {r})")).unwrap_or_default()));
                    if role.as_deref() == Some("embed") {
                        println!("{}", ui::note("the node advertises `embed` on its next gossip announce (about a minute); `noo cluster restart-agent <node>` forces it"));
                    }
                    ui::guide(&[
                        ("noo cluster status", "RUNNING column shows the backend once it has loaded the model"),
                        (&format!("noo cluster logs {node}"), "the node-agent log if the backend does not come up"),
                    ]);
                }
            }
            Err(e) => fail(g.json, ExitCode::Generic, "placement_failed", &format!("placement failed: {e}"), None),
        }
    } else if !g.json {
        ui::close_done(&format!("{name} imported on {node}"));
    }
    if g.json {
        println!("{}", json!({"status": "ok", "model": name, "node": node, "placed": place, "role": role}));
    }
    Ok(0)
}

/// Stage `<name>.Modelfile` + its weight into the store from the OCI
/// artifact `<NOO_IMAGE_PREFIX>/<name>:v1` (three files under /<name>/ —
/// the shape publish-harrier.yml produces). The Modelfile's `FROM ./x.gguf`
/// is rewritten to the bare filename the agent's importer requires.
/// Returns the file names written.
fn stage_artifact_into_store(name: &str, store: &std::path::Path) -> Result<Vec<String>, String> {
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("model name must be a single path component".into());
    }
    let prefix = {
        let p = super::provision::release_var("NOO_IMAGE_PREFIX");
        if p.is_empty() { crate::registry::IMAGE_NAMESPACE.to_string() } else { p.trim_end_matches('/').to_string() }
    };
    let artifact = format!("{prefix}/{name}:v1");
    std::fs::create_dir_all(store).map_err(|e| format!("create {}: {e}", store.display()))?;
    let tmp = store.join(format!(".{name}.staging"));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let src = format!("noo-artifact-{name}-{}", std::process::id());
    let rc = Command::new("bash").arg("-c")
        .arg(format!(
            "docker rm -f '{src}' >/dev/null 2>&1; docker pull -q '{artifact}' >/dev/null && \
             docker create --name '{src}' '{artifact}' >/dev/null && docker cp '{src}:/{name}/.' '{d}/'; rc=$?; \
             docker rm -f '{src}' >/dev/null 2>&1; exit $rc", d = tmp.display()))
        .status().map(|s| s.success()).unwrap_or(false);
    if !rc {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(format!("could not pull or unpack {artifact}"));
    }
    let mut written = Vec::new();
    for entry in std::fs::read_dir(&tmp).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let fname = entry.file_name().to_string_lossy().into_owned();
        let dest = store.join(&fname);
        if fname.to_ascii_lowercase().ends_with(".modelfile") {
            let body = std::fs::read_to_string(entry.path()).map_err(|e| e.to_string())?;
            let fixed: String = body.lines().map(|l| {
                match l.strip_prefix("FROM ./") { Some(rest) => format!("FROM {rest}"), None => l.to_string() }
            }).collect::<Vec<_>>().join("\n") + "\n";
            std::fs::write(&dest, fixed).map_err(|e| e.to_string())?;
        } else {
            std::fs::rename(entry.path(), &dest).or_else(|_| std::fs::copy(entry.path(), &dest).map(|_| ())).map_err(|e| e.to_string())?;
        }
        written.push(fname);
    }
    let _ = std::fs::remove_dir_all(&tmp);
    written.sort();
    Ok(written)
}

fn gguf_store_dir() -> PathBuf {
    let dir = env_value("MODELS_DIR");
    if !dir.is_empty() {
        return PathBuf::from(dir);
    }
    let root = env_value("NOO_DATA_ROOT");
    let root = if root.is_empty() { crate::commands::data_root::DEFAULT_DATA_ROOT.to_string() } else { root };
    PathBuf::from(root).join("models")
}

/// Publish one converted artifact into the GGUF store.
///
/// tmp+rename: the
/// gateway's digest cache is keyed on size+mtime, so a half-copied file that
/// stops growing would be hashed and served as truth.
fn publish_to_gguf_store(src: &std::path::Path, dest_name: &str) -> Result<PathBuf, String> {
    let dir = gguf_store_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let dest = dir.join(dest_name);
    let tmp = dir.join(format!("{dest_name}.publishing"));
    std::fs::copy(src, &tmp).map_err(|e| format!("copy {dest_name}: {e}"))?;
    std::fs::rename(&tmp, &dest).map_err(|e| format!("finalize {dest_name}: {e}"))?;
    Ok(dest)
}

fn is_self(node: &Value, ip: &str) -> bool {
    let node_id = node["id"].as_str().or_else(|| node["node_id"].as_str()).unwrap_or("").trim().to_string();
    let env_node_id = env_value("NODE_ID");
    if !node_id.is_empty() && !env_node_id.is_empty() && node_id == env_node_id.trim() {
        return true;
    }
    if let Ok(o) = Command::new("uname").arg("-n").output() {
        let h = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !node_id.is_empty() && node_id == h {
            return true;
        }
    }
    if ["127.0.0.1", "localhost", "::1"].contains(&ip) {
        return true;
    }
    if let Some(lan) = detect_lan_ip() {
        if lan == ip {
            return true;
        }
    }
    false
}

/// Ship IMAGE to a registered node over the artifact rail
/// step 2): export to the controller store, then ask the node's agent —
/// via the gateway proxy — to pull the digest-verified tar for ITS OWN
/// architecture and `docker load` it. No SSH anywhere on this path.
/// Returns the result string for the records ("ok" | "up_to_date"), or an
/// error message.
fn sync_image_via_pull(g: &Globals, image: &str, node_id: &str, arch: &str, restart: bool) -> Result<&'static str, String> {
    // Stage for the NODE's architecture: an arm64 node gets an arm64 tar,
    // pulled by platform with the controller's registry login
    // (image_stage.rs) — no more "not arm64-built, skipping".
    let rec = crate::commands::image_stage::stage_and_record(g, image, arch, "sync-images")?;
    let (tar_name, local_id) = (rec.tar, rec.image_id);
    // --restart maps to "remove the old container after a verified load":
    // the agent force-removes it and BackendManager / desired-state
    // recreates it on the new image at the next start. Deliberately NOT a
    // compose recreate over SSH — backends on workers are agent-managed.
    let remove_container = if restart { container_name_for_image(image).unwrap_or("") } else { "" };
    let body = json!({
        "kind": "image",
        "image": image,
        "image_id": local_id,
        "remove_container": remove_container,
    });
    if !g.json {
        say(&format!("  asking {node_id}'s agent to pull {tar_name}"));
    }
    let resp = post_json_try(
        g,
        &format!("/api/cluster/nodes/{}/pull", super::urlencode(node_id)),
        &body,
        true,
        2700, // a multi-GB tar over the LAN takes minutes; the pull is synchronous
    )
    .map_err(|e| format!("pull via agent failed: {e}"))?;
    match resp["status"].as_str() {
        Some("up_to_date") => Ok("up_to_date"),
        Some("loaded") => {
            if let Some(c) = resp["removed_container"].as_str().filter(|c| !c.is_empty()) {
                say(&format!("  {node_id}: removed {c} — next backend start recreates it on the new image"));
            }
            Ok("ok")
        }
        other => Err(format!("unexpected agent response status {other:?}: {resp}")),
    }
}

/// Ask an arm64 node's agent to build noo-sandbox-base itself.
///
/// The base is multi-arch upstream and the Dockerfile has no COPY steps, so a
/// node building locally gets its own architecture for free. What changed in
/// 2026-09 is only how the Dockerfile gets there: it used to be piped over
/// SSH into `docker build -`, and it is now EMBEDDED in the agent binary that
/// already rides the rail. The request carries no content at all — an
/// endpoint that built whatever it was sent would be remote code execution
/// wearing a build's clothes.
fn remote_build_sandbox_base(g: &Globals, node_id: &str) -> Result<(), String> {
    let resp = post_json_try(
        g,
        &format!("/api/cluster/nodes/{}/pull", super::urlencode(node_id)),
        &json!({ "kind": "sandbox-base" }),
        true,
        1500, // pulls python:3.12-slim on a slow SBC link before it builds
    )
    .map_err(|e| format!("build via agent failed: {e}"))?;
    match resp["status"].as_str() {
        Some("built") => Ok(()),
        other => Err(format!("unexpected agent response status {other:?}: {resp}")),
    }
}

/// Parsed `sync-images` flags — extracted from the handler so the arg /
/// image-list handling is unit-testable without a gateway or ssh.
///
/// The one image verb (i195 A7): phase 1 stages on the artifact rail, phase 2
/// has each named node's agent pull. `--stage-only` stops after phase 1;
/// `--lock`, `--arch` and `--all-images` are phase-1 selectors (they were
/// `stage-images`'s flags).
#[derive(Debug)]
struct SyncImagesArgs {
    nodes: Vec<String>,
    images: Vec<String>,
    restart: bool,
    /// `--restart` / `--no-restart` was spelled out (the default is restart).
    restart_given: bool,
    all: bool,
    stage_only: bool,
    lock: bool,
    arches: Vec<String>,
    all_images: bool,
}

fn parse_sync_images_args(args: &[String]) -> Result<SyncImagesArgs, Unhandled> {
    let mut a = SyncImagesArgs {
        nodes: Vec::new(), images: Vec::new(), restart: true, restart_given: false, all: false,
        stage_only: false, lock: false, arches: Vec::new(), all_images: false,
    };
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-i" | "--image" => a.images.push(iter.next().ok_or(Unhandled)?.clone()),
            "--images" => a.images.extend(split_image_list(iter.next().ok_or(Unhandled)?)),
            "--restart" => { a.restart = true; a.restart_given = true }
            "--no-restart" => { a.restart = false; a.restart_given = true }
            "--all" => a.all = true,
            "--stage-only" => a.stage_only = true,
            "--lock" => a.lock = true,
            "--all-images" => a.all_images = true,
            "--arch" => {
                for x in iter.next().ok_or(Unhandled)?.split(',') {
                    a.arches.push(crate::commands::image_stage::normalize_arch(x).ok_or(Unhandled)?.to_string());
                }
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => a.nodes.push(t.to_string()),
        }
    }
    Ok(a)
}

impl SyncImagesArgs {
    /// Flag combinations with no sensible meaning are refused with the reason,
    /// never guessed at.
    fn validate(&self) -> Result<(), &'static str> {
        if self.stage_only {
            if !self.nodes.is_empty() || self.all {
                return Err("--stage-only stops after staging on the artifact rail, so it takes no nodes and no --all; drop --stage-only to have nodes pull");
            }
            if self.restart_given {
                return Err("--restart/--no-restart acts on a node's container after its pull, and --stage-only has no pull");
            }
            if self.all_images && !(self.lock || self.images.is_empty()) {
                return Err("--all-images widens the lock's staged set; add --lock (it selects nothing when only -i images are staged)");
            }
        } else {
            if self.lock && self.nodes.is_empty() && !self.all {
                return Err("--lock stages the release images but nothing would pull them; name nodes (or --all), or use --stage-only to only stage");
            }
            if self.all_images {
                return Err("--all-images stages controller-only images no node can pull; use it with --stage-only");
            }
            if !self.arches.is_empty() {
                return Err("--arch applies to staging only, since each node pulls the tar for its own architecture; use it with --stage-only");
            }
        }
        Ok(())
    }
}

/// `--images a,b,c` → trimmed entries, empties dropped (`"a, ,b,"` → a, b).
fn split_image_list(csv: &str) -> Vec<String> {
    csv.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

/// First occurrence wins — `-i a --images a,b` ships `a` once, not twice.
fn dedupe_images(images: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    images.into_iter().filter(|i| seen.insert(i.clone())).collect()
}

/// Default image set when no `-i/--image/--images` is given: the
/// worker-relevant controller builds.
fn default_sync_images() -> Vec<String> {
    // noo-sandbox-base is the capability-sandbox base image (built
    // controller-side via the compose build-only profile) — without it,
    // unpinned sandbox runs 500 on workers with "pull access denied"
    // (it exists in no registry).
    // BOTH namespaces. The compose files build `noomesh/node-agent:latest`
    // since the monorepo rename; an install that has not rebuilt since still
    // has only `pai-assistant/node-agent:latest`. Syncing a list is
    // best-effort per image, so naming one that is absent costs nothing —
    // while naming only the new one would silently sync nothing on every
    // machine that has not rebuilt yet.
    let mut v = vec![
        "noomesh/node-agent:latest".to_string(),
        "pai-assistant/node-agent:latest".to_string(),
        "noo-sandbox-base:latest".to_string(),
    ];
    // …and the RELEASE ref, which is the one a released node actually asks
    // for and the only one the old default could not supply.
    //
    // A node's helper image (every host op — models dir, weight preseed —
    // runs in a container from it) is derived by the agent from the
    // NOO_IMAGE_PREFIX/NOO_IMAGE_TAG pair its env carries, so on a released
    // node it is `ghcr.io/noomesh/node-agent:<tag>` — a ref
    // this list did not contain. The result: `noo cluster sync-images host3`
    // reported success having shipped nothing the node would ever look for,
    // and unblocking host3 (v0.2.39) needed a hand-written
    // `-i ghcr.io/noomesh/node-agent:v0.2.39`. Deriving it
    // from the controller's own env is how the two sides agree without a
    // lookup table to drift from.
    if let Some(r) = release_node_agent_ref() {
        v.push(r);
    }
    v
}

/// `$NOO_IMAGE_PREFIX/node-agent:$NOO_IMAGE_TAG`, matching the agent's own
/// `helperImage()` derivation exactly. `None` when the controller env names
/// no release pair (a source install, where the `:latest` entries above are
/// the real images).
fn release_node_agent_ref() -> Option<String> {
    let prefix = std::env::var("NOO_IMAGE_PREFIX").unwrap_or_default();
    let prefix = prefix.trim().trim_end_matches('/').to_string();
    let tag = std::env::var("NOO_IMAGE_TAG").unwrap_or_default();
    let tag = tag.trim().to_string();
    if prefix.is_empty() || tag.is_empty() {
        return None;
    }
    Some(format!("{prefix}/node-agent:{tag}"))
}

/// Resolve a node argument: gateway record first (id or hostname), else the
/// `ansible/inventory/hosts` row the operator maintains — so one command still
/// ships images when the gateway is down or the node was never registered.
fn resolve_sync_node(gateway_nodes: &[Value], inventory: &[(String, String, String)], name: &str) -> Option<Value> {
    if let Some(n) = gateway_nodes
        .iter()
        .find(|n| n["id"].as_str() == Some(name) || n["hostname"].as_str() == Some(name))
    {
        return Some(n.clone());
    }
    inventory
        .iter()
        .find(|(n, _, _)| n == name)
        .map(|(n, host, user)| json!({"id": n, "ip_address": host, "ssh_user": user, "source": "inventory"}))
}

/// `noo cluster sync-images [NODES…] [-i/--image IMG]… [--images A,B,…]
/// [--restart/--no-restart] [--all] [--stage-only] [--lock] [--arch a,b]
/// [--all-images]` — export controller-built images into
/// the artifact store and have each node's agent pull the digest-verified tar
/// for its own architecture. No SSH at all as of
/// 2026-09: the last two lanes were the arm64 node-agent cross-build (which
/// duplicated two rails the agent already has) and the arm64 sandbox-base
/// build (which now happens agent-side from an embedded Dockerfile). Nodes
/// resolve via the gateway; inventory-only rows are refused (the rail needs
/// an agent). Images already on the node at the same ID are skipped
/// agent-side.
pub fn cluster_sync_images(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let parsed = parse_sync_images_args(args)?;
    if let Err(why) = parsed.validate() {
        fail(g.json, ExitCode::Usage, "usage", &format!("noo cluster sync-images: {why}"), Some("noo help cluster sync-images"));
    }
    if parsed.stage_only {
        return Ok(crate::commands::image_stage::run_stage_only(g, &parsed.images, &parsed.arches, parsed.lock, parsed.all_images));
    }
    let lock_refs = if parsed.lock {
        // Phase 1 from the lock, digest-verified; the nodes then pull exactly
        // the node-bound release images it staged (plus any -i image).
        let (lock, prefix, tag) = crate::commands::image_stage::read_controller_lock(g);
        let arches = crate::commands::image_stage::fleet_arches_from_gateway(g);
        let sum = crate::commands::image_stage::stage_lock(g, &lock, &prefix, &tag, &arches, false);
        for f in &sum.failed {
            ui::warned(f);
        }
        crate::commands::image_stage::lock_node_refs(&lock, &prefix, &tag)
    } else {
        Vec::new()
    };
    let (node_args, mut images, restart, all_nodes) =
        (parsed.nodes, parsed.images, parsed.restart, parsed.all);
    images.extend(lock_refs);

    let targets: Vec<Value> = if all_nodes {
        online_nodes(g)
    } else if !node_args.is_empty() {
        let gateway_nodes: Vec<Value> = get_json_opt(g, "/api/cluster/nodes", true, 10)
            .and_then(|b| b["nodes"].as_array().cloned())
            .unwrap_or_default();
        // Supplements the gateway list with ssh users/addresses. Was
        // `ansible/inventory/hosts` (deleted in 3695e129), which meant this
        // supplement had silently been empty on every install.
        let inventory = crate::commands::security_local::fleet_nodes_from_registry(g);
        node_args
            .iter()
            .map(|name| {
                resolve_sync_node(&gateway_nodes, &inventory, name).unwrap_or_else(|| {
                    let known: Vec<String> = gateway_nodes
                        .iter()
                        .filter_map(|n| n["id"].as_str().map(str::to_string))
                        .chain(inventory.iter().map(|(n, _, _)| n.clone()))
                        .collect();
                    fail(
                        g.json,
                        ExitCode::Generic,
                        "node_not_found",
                        &format!("Node '{name}' not found in the gateway registry"),
                        Some(&format!("known nodes: {}", known.join(", "))),
                    );
                })
            })
            .collect()
    } else {
        fail(g.json, ExitCode::Generic, "no_targets", "Specify node IDs as args, or pass --all", None);
    };
    if targets.is_empty() {
        if !g.json {
            say("No nodes resolved — nothing to do");
        }
        return Ok(0);
    }
    let images_to_ship = if images.is_empty() { default_sync_images() } else { dedupe_images(images) };

    let mut succeeded = 0;
    let mut failed = 0;
    let mut records: Vec<Value> = Vec::new();
    for node in &targets {
        let nid = node["id"].as_str().unwrap_or("?").to_string();
        let ip = node["ip_address"].as_str().or_else(|| node["ip"].as_str()).or_else(|| node["hostname"].as_str()).unwrap_or("").to_string();
        if ip.is_empty() {
            say(&format!("{nid}: no IP — skipping"));
            failed += 1;
            continue;
        }
        let mut is_arm = node["is_arm"].as_bool().unwrap_or(false) || node["capabilities"]["is_arm"].as_bool().unwrap_or(false);
        let tier = node["tier"].as_i64().or_else(|| node["capabilities"]["tier"].as_i64()).unwrap_or(0);
        if tier == 4 {
            is_arm = true;
        }
        for img in &images_to_ship {
            if !g.json {
                ui::step(&format!("{nid} ({ip}): {img}"));
            }
            if is_self(node, &ip) {
                let container = container_name_for_image(img);
                if restart {
                    if let Some(c) = container {
                        let rc = Command::new("docker").args(["restart", c]).output().map(|o| o.status.code().unwrap_or(1)).unwrap_or(1);
                        if rc == 0 {
                            say(&format!("  {nid}: local image already current — restarted {c}"));
                        } else {
                            say(&format!("  {nid}: local image already current — restart of {c} failed (rc={rc})"));
                        }
                    }
                } else {
                    say(&format!("  {nid}: local image already current — skipped (controller node)"));
                }
                succeeded += 1;
                records.push(json!({"node": nid, "image": img, "result": "self"}));
                continue;
            }
            if img.contains("node-agent") {
                // The agent has ONE rail: the signed provision bundle
                // (`noo cluster provision`, `noo upgrade --nodes`). The
                // gateway-signed /pull kind=binary swap was retired by
                // And this command's old arm64 path
                // (cross-compile, scp, compose recreate over SSH) went
                // before it.
                say(&format!("  {nid}: {img} travels in the signed provision bundle — `noo cluster provision {nid} --wait`; skipped here"));
                records.push(json!({"node": nid, "image": img, "result": "skipped_agent"}));
                continue;
            }
            if is_arm && img == "noo-sandbox-base:latest" {
                // The sandbox base has no COPY steps and its upstream base is
                // multi-arch, so an arm64 node builds it locally from the
                // Dockerfile embedded in its own agent — its own arch for
                // free, no cross-build, no registry, and no content in the
                // request.
                match remote_build_sandbox_base(g, &nid) {
                    Ok(()) => {
                        say(&format!("  {nid}: noo-sandbox-base built natively (arm64)"));
                        succeeded += 1;
                        records.push(json!({"node": nid, "image": img, "result": "ok"}));
                    }
                    Err(e) => {
                        say(&format!("  {nid}: sandbox-base build failed — {e}"));
                        failed += 1;
                        records.push(json!({"node": nid, "image": img, "result": "failed"}));
                    }
                }
                continue;
            }
            // A node resolved only from the ansible inventory has no live
            // agent registration — and the pull rail runs THROUGH the
            // agent. Refusing beats silently reviving the SSH path.
            if node["source"].as_str() == Some("inventory") {
                say(&format!("  {nid}: not registered with the gateway — the pull rail needs a live agent (enroll/start the node first)"));
                failed += 1;
                records.push(json!({"node": nid, "image": img, "result": "no_agent"}));
                continue;
            }
            let arch = crate::commands::image_stage::node_arch(node)
                .map(str::to_string)
                .unwrap_or_else(|| if is_arm { "arm64".to_string() } else { crate::commands::image_stage::host_arch() });
            match sync_image_via_pull(g, img, &nid, &arch, restart) {
                Ok("up_to_date") => {
                    say(&format!("  {nid}: already present at the same image ID — skipped"));
                    succeeded += 1;
                    records.push(json!({"node": nid, "image": img, "result": "up_to_date"}));
                }
                Ok(_) => {
                    say(&format!("  {nid}: {img} pulled + loaded (digest-verified)"));
                    succeeded += 1;
                    records.push(json!({"node": nid, "image": img, "result": "ok"}));
                }
                Err(e) if e.starts_with(crate::commands::image_stage::NO_VARIANT) => {
                    let hint = if img.contains("llamacpp") {
                        "an ARM node runs the upstream llama.cpp image; stage it with -i ghcr.io/ggml-org/llama.cpp:server"
                    } else {
                        "stage a multi-arch equivalent with -i <image>"
                    };
                    say(&format!("  {nid}: {img} is not published for {arch} — skipping ({hint})."));
                    records.push(json!({"node": nid, "image": img, "result": "skipped_arch"}));
                }
                Err(e) => {
                    say(&format!("  {nid}: {e}"));
                    failed += 1;
                    records.push(json!({"node": nid, "image": img, "result": "failed"}));
                }
            }
        }
    }
    if g.json {
        println!("{}", json!({"succeeded": succeeded, "failed": failed, "results": records}));
    } else if failed == 0 {
        ui::close_done(&format!("sync complete: {succeeded} ok"));
    } else {
        ui::close_warned(&format!("sync done: {succeeded} ok, {failed} failed"));
    }
    Ok(if failed == 0 { 0 } else { 1 })
}

// ════════════════════════════════════════════════════════════════════
//  ship-model — convert an HF model locally + ship to a node's Ollama
// ════════════════════════════════════════════════════════════════════

/// `noo cluster ship-model HF_ID NODE [--name N] [--quant Q] [--place]
/// [-b/--backend B]` — run scripts/noo-model-convert.sh locally → GGUF +
/// Modelfile, publish the pair into the controller's artifact store, and ask
/// NODE's agent to fetch it and `ollama create`. With --place, declares a
/// desired-state placement. The convert STREAMS (inherited terminal).
///
/// This was the last `ssh`/`scp` in the CLI. Its ship half duplicated
/// `preseedGGUF`, which had been pulling digest-verified GGUFs from this
/// exact store for months; its create half needed a transport the mesh
/// retired. The artifacts are published BEFORE the node is
/// asked for anything, so a failed import is retried without reconverting.
pub fn cluster_ship_model(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positional: Vec<String> = Vec::new();
    let mut name: Option<String> = None;
    let mut quant = "Q4_K_M".to_string();
    let mut place = false;
    let mut backend = "embedding".to_string();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--name" => name = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--quant" => quant = iter.next().ok_or(Unhandled)?.clone(),
            "--place" => place = true,
            "-b" | "--backend" => backend = iter.next().ok_or(Unhandled)?.clone(),
            t if t.starts_with('-') => return Err(Unhandled),
            t => positional.push(t.to_string()),
        }
    }
    let [hf_id, node] = positional.as_slice() else { return Err(Unhandled) };
    let name = name.unwrap_or_else(|| hf_id.rsplit('/').next().unwrap_or(hf_id).to_lowercase());

    let root = repo_root();
    let script = root.join("scripts").join("noo-model-convert.sh");
    if !script.exists() {
        fail(g.json, ExitCode::Generic, "no_script", &format!("convert script not found: {}", script.display()),
            Some("ship-model runs scripts/noo-model-convert.sh from a source checkout; run it from one (or set NOO_REPO_ROOT)"));
    }

    // 1. Confirm the node is registered BEFORE converting. The conversion
    // is a llama.cpp build and can run for many minutes; discovering the
    // node's name was wrong at the end of it is the expensive way to learn.
    // Nothing but the name is needed now — the rail addresses the node
    // through the gateway, so there is no IP or account to resolve.
    let body = get_json(g, "/api/cluster/nodes", true, 10);
    let empty = Vec::new();
    let registered = body["nodes"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .any(|n| n["id"].as_str() == Some(node.as_str()) || n["node_id"].as_str() == Some(node.as_str()));
    if !registered {
        fail(g.json, ExitCode::Generic, "node_not_found", &format!("node '{node}' not found in the cluster"), None);
    }

    // 2. Convert locally → GGUF + Modelfile. The convert script is a long
    // llama.cpp build/convert log; it keeps the terminal (inherited) so the
    // operator can watch it — it is the one place this command streams.
    let workdir = root.join(".model-convert");
    if !g.json {
        println!("{}", ui::phase("Convert"));
        ui::step(&format!("converting {hf_id} → GGUF ({quant}, local)"));
    }
    std::env::set_var("WORKDIR", &workdir);
    std::env::set_var("NOO_CONVERT_GGUF_ONLY", "1");
    let rc = spawn_inherited(g, "bash", &[script.to_string_lossy().to_string(), hf_id.clone(), name.clone(), quant.clone()]);
    if rc != 0 {
        fail(g.json, ExitCode::Generic, "convert_failed", "conversion failed", None);
    }
    let gguf = workdir.join(format!("{name}-{quant}.gguf"));
    let modelfile = workdir.join(format!("{name}.Modelfile"));
    if !gguf.exists() || !modelfile.exists() {
        fail(
            g.json,
            ExitCode::Generic,
            "artifacts_missing",
            &format!("expected artifacts missing: {} / {}", gguf.file_name().and_then(|s| s.to_str()).unwrap_or("?"), modelfile.file_name().and_then(|s| s.to_str()).unwrap_or("?")),
            None,
        );
    }

    // 3. Publish both artifacts into the controller's GGUF store, where
    // nginx serves them and the gateway can manifest their digests. They go
    // together and keep their names: the Modelfile's `FROM ./<file>` is how
    // the node learns which weight to fetch, so the pair is the unit.
    if !g.json {
        ui::done(&format!("converted: {}", gguf.file_name().and_then(|s| s.to_str()).unwrap_or("?")));
        println!("{}", ui::phase("Publish"));
        let mb = std::fs::metadata(&gguf).map(|m| m.len() as f64 / 1_048_576.0).unwrap_or(0.0);
        ui::step(&format!("publishing {} ({mb:.1} MB) + its Modelfile to the artifact store", gguf.file_name().and_then(|s| s.to_str()).unwrap_or("?")));
    }
    let gguf_name = gguf.file_name().and_then(|s| s.to_str()).unwrap_or("model.gguf").to_string();
    let mf_name = modelfile.file_name().and_then(|s| s.to_str()).unwrap_or("Modelfile").to_string();
    for (src, dest_name) in [(&gguf, &gguf_name), (&modelfile, &mf_name)] {
        if let Err(e) = publish_to_gguf_store(src, dest_name) {
            fail(g.json, ExitCode::Generic, "publish_failed", &format!("could not publish {dest_name}: {e}"), None);
        }
    }
    if !g.json {
        ui::done(&format!("published to {}", gguf_store_dir().display()));
    }

    // 4. Ask the node's agent to fetch the pair and run `ollama create`.
    //
    // The request carries a NAME, never the Modelfile: a Modelfile is a
    // recipe the ollama daemon executes, so a body that carried one would
    // make /pull a remote-execution endpoint. The agent fetches both files
    // from the store and verifies both digests first.
    if !g.json {
        println!("{}", ui::phase("Create"));
        ui::step(&format!("{node}'s agent is fetching the pair and running ollama create {name}"));
    }
    match post_json_try(
        g,
        &format!("/api/cluster/nodes/{}/pull", super::urlencode(node)),
        &json!({ "kind": "ollama-model", "name": name }),
        true,
        3600, // a multi-GB fetch over the LAN, then the import
    ) {
        Ok(resp) => {
            if !g.json {
                let via = resp["via"].as_str().unwrap_or("?");
                ui::done(&format!("{name} created on {node} (via the {via} ollama)"));
            }
        }
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "create_failed",
            &format!("the node could not import the model: {e}"),
            Some("the artifacts ARE published — re-run to retry the import without reconverting"),
        ),
    }

    // 5. Optional desired-state placement.
    if place {
        if !g.json {
            println!("{}", ui::phase("Place"));
            ui::step(&format!("placing {name} as {backend} on {node}"));
        }
        match post_json_try(g, "/api/cluster/backends/start", &json!({"backend": backend, "model": name, "node_id": node}), true, 60) {
            Ok(_) => {
                if g.json {
                    println!("{}", json!({"status": "ok", "model": name, "node": node, "placed": true, "backend": backend}));
                } else {
                    ui::close_done(&format!("{name} shipped and placed on {node}"));
                    ui::guide(&[
                        ("noo cluster status", "RUNNING column shows the backend once it has loaded the model"),
                        (&format!("noo cluster logs {node}"), "the node-agent log if the backend does not come up"),
                    ]);
                }
            }
            Err(e) => fail(g.json, ExitCode::Generic, "placement_failed", &format!("placement failed: {e}"), None),
        }
    } else if g.json {
        println!("{}", json!({"status": "ok", "model": name, "node": node, "placed": false}));
    } else {
        ui::close_done(&format!("{name} shipped to {node}"));
        ui::guide(&[
            (&format!("noo cluster place {node} {backend} {name}"), "pins the model to this node's backend; the scheduler routes to it on the next reconcile"),
            (&format!("noo cluster desired {node}"), "shows the placement once pinned"),
        ]);
    }
    Ok(0)
}

// ════════════════════════════════════════════════════════════════════
//  clean — destructive multi-node Docker cleanup, over the agent
// ════════════════════════════════════════════════════════════════════

/// `noo cluster clean NODE|all [--deep] [-y/--yes]` — remove this
/// deployment's containers (and with `--deep`, its images) on the target
/// node(s). Does NOT touch model data. DESTRUCTIVE → agent-first confirm
/// (`--yes` skips; --json/non-TTY refuse to block).
///
/// Rides `POST /api/cluster/nodes/{id}/clean`, which the gateway proxies to
/// the agent's own `/clean`. That endpoint has existed the whole time; this
/// command shelled out over SSH beside it until 2026-09.
///
/// The SSH version could not fail. Its remote command was a `;`-separated
/// list with `2>/dev/null` on every step, no `set -e`, ending in `echo done`
/// — and a `;` list exits with the status of its LAST command, so ssh
/// returned 0 whatever happened and every node was reported `cleaned`.
/// The agent returns COUNTS instead, which is an answer rather than an echo.
fn clean_one(g: &Globals, node_id: &str, deep: bool) -> Result<(u64, u64, bool), String> {
    let resp = post_json_try(
        g,
        &format!("/api/cluster/nodes/{}/clean", super::urlencode(node_id)),
        &json!({ "deep": deep }),
        true,
        180,
    )
    .map_err(|e| e.to_string())?;
    let containers = resp["containers_stopped"].as_u64().unwrap_or(0);
    let images = resp["images_removed"].as_u64().unwrap_or(0);
    // An agent older than the `deep` field has no `deep` key in its reply and
    // removes images unconditionally. Report what it DID.
    let honoured_deep = resp.get("deep").and_then(|v| v.as_bool());
    let old_agent = honoured_deep.is_none() && !deep && images > 0;
    Ok((containers, images, old_agent))
}

pub fn cluster_clean(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut node: Option<String> = None;
    let mut deep = false;
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            "--deep" => deep = true,
            "-y" | "--yes" => yes = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t if node.is_none() => node = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let Some(node) = node else {
        fail(g.json, ExitCode::Generic, "node_required", "Specify a node ID or 'all'", Some("noo cluster clean host8  |  noo cluster clean all"));
    };

    // Confirm before resolving nodes (agent-first; --yes skips, non-TTY/json refuse).
    super::confirm_destructive(
        g,
        yes,
        if deep { "Clean containers AND images on" } else { "Clean containers on" },
        &node,
    );

    let nodes: Vec<Value> = if node.eq_ignore_ascii_case("all") {
        let local = Command::new("uname").arg("-n").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
        let remote: Vec<Value> = online_nodes(g)
            .into_iter()
            .filter(|n| n["id"].as_str() != Some(local.as_str()) && n["hostname"].as_str() != Some(local.as_str()))
            .collect();
        if remote.is_empty() {
            if !g.json {
                say("No remote nodes found (controller excluded)");
            }
            return Ok(0);
        }
        if !g.json {
            say(&format!("Cleaning {} remote node(s)...\n", remote.len()));
        }
        remote
    } else {
        vec![fetch_node(g, &node)]
    };

    let mut success = 0;
    let mut records: Vec<Value> = Vec::new();
    for n in &nodes {
        let nid = n["id"].as_str().unwrap_or("?").to_string();
        if !g.json {
            say(&ui::item(&nid));
        }
        match clean_one(g, &nid, deep) {
            Ok((containers, images, old_agent)) => {
                if !g.json {
                    let detail = if deep {
                        format!("{containers} container(s), {images} image(s) removed")
                    } else {
                        format!("{containers} container(s) removed")
                    };
                    say(&ui::sub(&ui::status_line(Glyph::Ok, &detail)));
                    if old_agent {
                        say(&ui::sub(&ui::note(&format!(
                            "this agent predates --deep and removed {images} image(s) anyway — \
                             restage it with `noo cluster provision {nid} --wait`"))));
                    }
                }
                success += 1;
                records.push(json!({
                    "node": nid, "result": "cleaned",
                    "containers_stopped": containers, "images_removed": images,
                    "deep_honoured": !old_agent,
                }));
            }
            Err(e) => {
                if !g.json {
                    say(&ui::sub(&ui::status_line(Glyph::Err, "clean failed")));
                    ui::capture("agent said", &e.trim().chars().take(400).collect::<String>());
                }
                records.push(json!({"node": nid, "result": "failed", "detail": e}));
            }
        }
    }
    let failed = nodes.len() - success;
    if g.json {
        println!("{}", json!({"cleaned": success, "total": nodes.len(), "results": records}));
    } else if failed == 0 {
        ui::close_done(&format!("cleaned {success}/{} nodes", nodes.len()));
    } else {
        ui::close_warned(&format!("cleaned {success}/{} nodes", nodes.len()));
        ui::guide(&[
            ("noo cluster status", "a node that is not ONLINE has no agent to clean through"),
            ("noo cluster clean <node>", "retry one node once its agent is back"),
        ]);
    }
    // The SSH version returned Ok(0) even when nodes failed. A destructive
    // command that cannot report failure is worse than one that does nothing.
    Ok(if failed > 0 { 1 } else { 0 })
}

// ════════════════════════════════════════════════════════════════════
//  upgrade-agents — restage node agents over the bundle rail
// ════════════════════════════════════════════════════════════════════


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeArch {
    Arm,
    X86,
}

/// Normalise any architecture spelling we might be handed (`runtime.GOARCH`,
/// `uname -m`, docker's `.Architecture`). Unknown → None, never a guess.
pub(crate) fn arch_from_str(s: &str) -> Option<NodeArch> {
    match s.trim().to_ascii_lowercase().as_str() {
        "arm64" | "aarch64" | "aarch64_be" | "arm" | "armv6l" | "armv7l" | "armhf" | "armel" => Some(NodeArch::Arm),
        "amd64" | "x86_64" | "x64" | "x86" | "i386" | "i686" => Some(NodeArch::X86),
        _ => None,
    }
}

/// The architecture a node record CLAIMS, plus which field said so — or
/// `None` when the record carries no architecture signal at all.
///
/// `None` is a real answer and must stay one. The old code was
/// `n["is_arm"].as_bool().unwrap_or(false)`, which turned "the gateway never
/// persisted this" into "it's x86" and then streamed an x86_64 image onto an
/// aarch64 board — `exec /bin/sh: exec format error`, `Restarting (255)`, node
/// stranded. That is the fail-open this returns `None` for instead.
///
/// `capabilities.arch` is checked FIRST because it is the agent's own
/// `runtime.GOARCH`, re-sent every heartbeat; the flat `is_arm` column is a
/// derived copy that demonstrably goes stale (on 2026-08-04 `host9-sensors`
/// had `is_arm=f` in `cluster_nodes` while its own capabilities said
/// `arch=arm64, is_arm=true`).
/// Tier-5 companions are container-mode sensor proxies — never rail
/// targets. The nodes API emits `tier`, not `node_type` (checking the
/// latter was the bug that let bare rolls drain host9-sensors).
///
/// The other half of that lesson used to live in `agent_target_for`, which
/// mapped a `-sensors` id to its own compose service and container. It was
/// deleted with the SSH lane it served: on 2026-08-04 a roll recreated
/// `node-agent` for BOTH agents on 100.64.0.13, so the sensors step
/// destroyed host9's container and reported success for one it never
/// touched. Nothing in this file recreates a container on a node any more —
/// the agent's own hostd owns that — so the mapping had no caller left. If a
/// controller-side container recreate ever comes back, it comes back with
/// that mapping, not without it.
pub(crate) fn is_companion(n: &serde_json::Value) -> bool {
    n["tier"].as_i64() == Some(5) || n["node_type"].as_str() == Some("companion")
}

pub(crate) fn node_arch_signal(n: &Value) -> Option<(NodeArch, &'static str)> {
    if let Some(a) = n["capabilities"]["arch"].as_str().and_then(arch_from_str) {
        return Some((a, "capabilities.arch"));
    }
    if let Some(a) = n["arch"].as_str().and_then(arch_from_str) {
        return Some((a, "arch"));
    }
    if let Some(b) = n["capabilities"]["is_arm"].as_bool() {
        return Some((if b { NodeArch::Arm } else { NodeArch::X86 }, "capabilities.is_arm"));
    }
    if let Some(b) = n["is_arm"].as_bool() {
        return Some((if b { NodeArch::Arm } else { NodeArch::X86 }, "is_arm"));
    }
    None
}

/// The note `upgrade-agents` prints before it does anything: what it does now,
/// and why it no longer does what it used to.
pub(crate) const UPGRADE_AGENTS_RAIL_NOTE: &str =
    "upgrade-agents now restages each node's signed provision bundle over the pull rail \
     (the bundle carries the agent binary; the node's applier installs it with a \
     health-checked restart). The gateway-signed agent swap it used to drive \
     (`/pull kind=binary` + hostd swap-agent) is retired.";

/// Flags of the retired swap roll. Accepted so an existing script does not
/// break, and named in a note so nobody believes they still do something.
const RETIRED_SWAP_FLAGS: &[&str] = &["--skip-build", "--drain-grace", "--health-timeout"];

/// Parsed `upgrade-agents` arguments: the named nodes, `-y`, and which
/// retired flags were given (each value-taking one consumes its value).
#[derive(Debug, Default, PartialEq)]
pub(crate) struct UpgradeAgentsArgs {
    pub nodes: Vec<String>,
    pub yes: bool,
    pub ignored: Vec<String>,
}

pub(crate) fn parse_upgrade_agents_args(args: &[String]) -> Result<UpgradeAgentsArgs, Unhandled> {
    let mut out = UpgradeAgentsArgs::default();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--skip-build" => out.ignored.push(tok.clone()),
            "--drain-grace" | "--health-timeout" => {
                iter.next().and_then(|v| v.parse::<u64>().ok()).ok_or(Unhandled)?;
                out.ignored.push(tok.clone());
            }
            "-y" | "--yes" => out.yes = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => out.nodes.push(t.to_string()),
        }
    }
    Ok(out)
}

/// The child command each node gets: the same restage `noo upgrade --nodes`
/// runs, waiting for the node's own apply report. Nothing here talks to an
/// agent's `/pull` — the bundle is the only way code reaches a node.
pub(crate) fn upgrade_agents_child_args(node: &str) -> Vec<String> {
    vec!["cluster".into(), "provision".into(), node.into(), "--wait".into()]
}

/// `noo cluster upgrade-agents [NODES…] [-y]` — restage the provision bundle
/// for each target, serially, over the pull rail, each in a child
/// `noo cluster provision <node> --wait` (so one node's failure is reported
/// and the next is still attempted). Default targets: online/busy remote
/// nodes, never the controller itself (`noo upgrade --nodes` covers its local
/// agent) and never a tier-5 companion (container-mode, no bundle applier).
///
/// Before an earlier release this cross-built the agent, exported it into the
/// gateway's artifact store and asked each agent to pull it with
/// `/pull kind=binary`; the worker hostd then installed it as root on the
/// strength of a manifest signed by the GATEWAY's TLS key. That lane is gone:
/// the gateway refuses the manifest, the agent refuses the pull, hostd
/// refuses the swap.
pub fn cluster_upgrade_agents(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let parsed = parse_upgrade_agents_args(args)?;
    if !g.json {
        say(&ui::note(UPGRADE_AGENTS_RAIL_NOTE));
        if !parsed.ignored.is_empty() {
            say(&ui::note(&format!(
                "ignored: {} — {} belonged to the retired swap roll",
                parsed.ignored.join(" "),
                RETIRED_SWAP_FLAGS.join(", ")
            )));
        }
    }

    let body = get_json(g, "/api/cluster/nodes", true, 10);
    let empty = Vec::new();
    let registered: Vec<Value> = body["nodes"].as_array().unwrap_or(&empty).iter().filter(|n| n["id"].is_string()).cloned().collect();
    let local = Command::new("uname").arg("-n").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();

    let targets: Vec<String> = if !parsed.nodes.is_empty() {
        parsed.nodes.clone()
    } else {
        registered
            .iter()
            .filter(|n| {
                let id = n["id"].as_str().unwrap_or("");
                id != local && matches!(n["status"].as_str(), Some("online") | Some("busy")) && !is_companion(n)
            })
            .filter_map(|n| n["id"].as_str().map(String::from))
            .collect()
    };
    let targets: Vec<String> = targets.into_iter().filter(|t| *t != local).collect();
    let (targets, skipped_companions): (Vec<String>, Vec<String>) = targets.into_iter().partition(|t| {
        registered.iter().find(|n| n["id"].as_str() == Some(t.as_str())).map(|n| !is_companion(n)).unwrap_or(true)
    });
    if !g.json {
        for c in &skipped_companions {
            say(&format!(
                "{c}: skipped — tier-5 companion (container-mode sensor proxy, no bundle applier). \
                 Upgrade it by recreating the container from a current image."
            ));
        }
    }
    if targets.is_empty() {
        if !g.json {
            say("No remote worker nodes to upgrade.");
        }
        return Ok(0);
    }
    if !g.json {
        say(&ui::emph("restage plan (serial, signed bundles over the pull rail)"));
        for t in &targets {
            say(&ui::status_line(Glyph::Bullet, t));
        }
    }
    super::confirm_destructive(g, parsed.yes, "Restage the provision bundle (agent included) for", &format!("{} node(s)", targets.len()));

    let exe = std::env::current_exe().ok();
    let mut results: Vec<(String, String)> = Vec::new();
    for nid in &targets {
        let rc = match &exe {
            Some(exe) => {
                let mut cmd = Command::new(exe);
                if g.json { cmd.arg("--json"); }
                if g.verbose { cmd.arg("--verbose"); }
                if let Some(u) = &g.gateway_override { cmd.arg("--gateway").arg(u); }
                // The token travels in the child's ENVIRONMENT (auth::resolve
                // reads $NOO_TOKEN after --token), never on its argv, where
                // any local user could read it from /proc/<pid>/cmdline.
                if let Some(t) = &g.token { cmd.env("NOO_TOKEN", t); }
                cmd.args(upgrade_agents_child_args(nid));
                cmd.status().map(|s| s.code().unwrap_or(1)).unwrap_or(1)
            }
            None => {
                let a: Vec<String> = upgrade_agents_child_args(nid).into_iter().skip(2).collect();
                crate::commands::provision::cluster_provision(g, &a).unwrap_or(1)
            }
        };
        results.push((nid.clone(), if rc == 0 { "upgraded".into() } else { format!("FAILED (provision exit {rc})") }));
    }

    let any_failed = results.iter().any(|(_, s)| s != "upgraded");
    if g.json {
        println!(
            "{}",
            json!({"results": results.iter().map(|(n, s)| json!({"node": n, "status": s})).collect::<Vec<_>>(), "lane": "bundle-rail"})
        );
    } else {
        say(&ui::section("upgrade summary"));
        for (nid, status) in &results {
            let glyph = if status == "upgraded" { Glyph::Ok } else { Glyph::Err };
            say(&format!("  {} {nid}  {}", ui::glyph_cell(glyph), ui::state(status)));
        }
        if any_failed {
            say(&ui::note("a failed node kept its previous state; fix the cause shown above and re-run `noo cluster provision <node> --wait`"));
        }
    }
    Ok(if any_failed { 1 } else { 0 })
}



#[cfg(test)]
mod upgrade_agents_tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // ── C. no architecture signal must refuse, never default to amd64 ──

    #[test]
    fn node_with_no_arch_signal_is_refused_not_assumed_amd64() {
        let n = json!({"id": "mystery", "ip": "10.0.0.9", "status": "online"});
        assert!(node_arch_signal(&n).is_none(), "absent arch must stay unknown, not become x86");
    }

    #[test]
    fn capabilities_arch_outranks_a_stale_is_arm_column() {
        // Exactly host9-sensors on 2026-08-04: flat column says x86, the
        // agent's own capabilities say arm64. The agent wins.
        let n = json!({
            "id": "host9-sensors",
            "is_arm": false,
            "capabilities": {"arch": "arm64", "is_arm": true},
        });
        assert_eq!(node_arch_signal(&n), Some((NodeArch::Arm, "capabilities.arch")));
    }

    #[test]
    fn arch_signal_reads_every_supported_shape() {
        assert_eq!(node_arch_signal(&json!({"is_arm": true})), Some((NodeArch::Arm, "is_arm")));
        assert_eq!(node_arch_signal(&json!({"is_arm": false})), Some((NodeArch::X86, "is_arm")));
        assert_eq!(node_arch_signal(&json!({"arch": "x86_64"})), Some((NodeArch::X86, "arch")));
        assert_eq!(
            node_arch_signal(&json!({"capabilities": {"is_arm": true}})),
            Some((NodeArch::Arm, "capabilities.is_arm"))
        );
        // An unrecognised arch string is NOT a signal — fall through, and if
        // nothing else answers, stay unknown.
        assert!(node_arch_signal(&json!({"arch": "riscv64"})).is_none());
    }

    #[test]
    fn arch_strings_normalise_without_guessing() {
        for s in ["arm64", "aarch64", "armv7l", "ARM64", " arm64 "] {
            assert_eq!(arch_from_str(s), Some(NodeArch::Arm), "{s}");
        }
        for s in ["amd64", "x86_64", "X86_64"] {
            assert_eq!(arch_from_str(s), Some(NodeArch::X86), "{s}");
        }
        for s in ["", "unknown", "riscv64", "ppc64le"] {
            assert_eq!(arch_from_str(s), None, "{s}");
        }
    }


    /// Each node is restaged over the bundle rail. Fails on
    /// the pre-retirement roll, which posted `/pull kind=binary` instead.
    #[test]
    fn each_node_is_restaged_over_the_bundle_rail() {
        assert_eq!(upgrade_agents_child_args("host3"), args(&["cluster", "provision", "host3", "--wait"]));
    }

    /// The negative: nothing in this file asks an agent for a binary any
    /// more — the request body the swap roll built is gone, and so is the
    /// export into the gateway's bin store.
    #[test]
    fn the_retired_swap_lane_is_not_called() {
        let src = include_str!("cluster_provision_subprocess.rs");
        let body = ["\"kind\": \"", "binary\""].concat();
        assert!(!src.contains(&body), "upgrade-agents must not post /pull kind=binary");
        let export = ["fn export_", "agent_binary"].concat();
        assert!(!src.contains(&export), "the bin-store export went with the swap lane");
        assert!(UPGRADE_AGENTS_RAIL_NOTE.contains("retired"));
    }

    /// A child `noo` gets the operator's token through NOO_TOKEN, never
    /// `--token <secret>` on its argv (readable via /proc/<pid>/cmdline).
    /// Covers this roll and `noo upgrade`'s provision_one.
    #[test]
    fn child_spawns_never_put_the_token_on_argv() {
        let needle = [".arg(\"--token", "\")"].concat();
        for (name, src) in [
            ("cluster_provision_subprocess.rs", include_str!("cluster_provision_subprocess.rs")),
            ("upgrade.rs", include_str!("upgrade.rs")),
        ] {
            assert!(!src.contains(&needle), "{name} passes --token on a child's argv");
            assert!(src.contains("cmd.env(\"NOO_TOKEN\", t)"), "{name} no longer forwards the token by env");
        }
    }

    #[test]
    fn retired_flags_are_accepted_and_named_not_honoured() {
        let p = parse_upgrade_agents_args(&args(&["host3", "--skip-build", "--drain-grace", "5", "--health-timeout", "9", "-y"])).unwrap();
        assert_eq!(p.nodes, args(&["host3"]));
        assert!(p.yes);
        assert_eq!(p.ignored, args(&["--skip-build", "--drain-grace", "--health-timeout"]));
        // A value-taking retired flag still needs its value — a missing one
        // is a usage error, not a node name.
        assert!(parse_upgrade_agents_args(&args(&["--drain-grace"])).is_err());
        assert!(parse_upgrade_agents_args(&args(&["--bogus"])).is_err());
    }
}

#[cfg(test)]
mod sync_images_tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // ── the default set ──

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The bare `noo cluster sync-images <node>` used to ship only the
    /// unprefixed local build names, so on a RELEASED node it reported
    /// success having shipped nothing the node would ever ask for: the
    /// agent derives its helper image from NOO_IMAGE_PREFIX/NOO_IMAGE_TAG,
    /// so it looks for `ghcr.io/…/node-agent:v0.2.39`. Unblocking host3
    /// needed a hand-written `-i` for exactly that ref (R50).
    ///
    /// Serialised: these are process-wide env vars.
    #[test]
    fn default_set_covers_the_release_helper_ref() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // A released controller.
        std::env::set_var("NOO_IMAGE_PREFIX", "ghcr.io/noomesh");
        std::env::set_var("NOO_IMAGE_TAG", "v0.2.39");
        let set = default_sync_images();
        assert!(
            set.iter().any(|i| i == "ghcr.io/noomesh/node-agent:v0.2.39"),
            "the release ref a released node actually asks for is missing: {set:?}"
        );
        // The local builds stay: an install that has not rebuilt since the
        // rename still has only those, and a named-but-absent image costs
        // nothing (the export is best-effort per image).
        assert!(set.iter().any(|i| i == "noomesh/node-agent:latest"), "{set:?}");
        assert!(set.iter().any(|i| i == "noo-sandbox-base:latest"), "{set:?}");

        // A source install names no release pair: no phantom ref.
        std::env::remove_var("NOO_IMAGE_PREFIX");
        std::env::remove_var("NOO_IMAGE_TAG");
        let set = default_sync_images();
        assert!(
            !set.iter().any(|i| i.contains("ghcr.io")),
            "with no release pair there is nothing to derive: {set:?}"
        );

        // A half-set pair is not a ref either — `prefix/node-agent:` would
        // be a tar name nothing exports.
        std::env::set_var("NOO_IMAGE_PREFIX", "ghcr.io/x");
        std::env::set_var("NOO_IMAGE_TAG", "");
        assert_eq!(release_node_agent_ref(), None, "an empty tag must not build a ref");
        std::env::remove_var("NOO_IMAGE_PREFIX");
        std::env::remove_var("NOO_IMAGE_TAG");
    }

    /// The derivation must match the agent's `helperImage()` byte for byte,
    /// including the trailing-slash tolerance — the convention IS the
    /// protocol, there is no lookup table to drift from.
    #[test]
    fn release_ref_matches_the_agent_derivation() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NOO_IMAGE_PREFIX", "ghcr.io/noomesh/");
        std::env::set_var("NOO_IMAGE_TAG", "v1.2.3");
        assert_eq!(
            release_node_agent_ref().unwrap(),
            "ghcr.io/noomesh/node-agent:v1.2.3",
            "a trailing slash on the prefix must not double up"
        );
        std::env::remove_var("NOO_IMAGE_PREFIX");
        std::env::remove_var("NOO_IMAGE_TAG");
    }

    // ── arg parsing ──

    #[test]
    fn stage_only_flag_parses_and_defaults_off() {
        assert!(!parse_sync_images_args(&args(&["host8"])).unwrap().stage_only);
        let a = parse_sync_images_args(&args(&["--stage-only"])).unwrap();
        assert!(a.stage_only && a.nodes.is_empty());
        assert!(a.validate().is_ok());
    }

    #[test]
    fn lock_flag_parses_and_nodes_may_pull_it() {
        let a = parse_sync_images_args(&args(&["--lock", "host8"])).unwrap();
        assert!(a.lock && !a.stage_only);
        assert!(a.validate().is_ok(), "named nodes pull the staged lock set");
        assert!(parse_sync_images_args(&args(&["--stage-only", "--lock"])).unwrap().validate().is_ok());
    }

    #[test]
    fn arch_flag_normalizes_splits_and_rejects_unknown() {
        let a = parse_sync_images_args(&args(&["--stage-only", "--arch", "x86_64,aarch64"])).unwrap();
        assert_eq!(a.arches, vec!["amd64", "arm64"]);
        assert!(a.validate().is_ok());
        assert!(parse_sync_images_args(&args(&["--stage-only", "--arch", "riscv"])).is_err());
        assert!(parse_sync_images_args(&args(&["--stage-only", "--arch"])).is_err());
    }

    #[test]
    fn all_images_flag_parses_with_lock_under_stage_only() {
        let a = parse_sync_images_args(&args(&["--stage-only", "--lock", "--all-images"])).unwrap();
        assert!(a.all_images && a.validate().is_ok());
        // No -i: the lock is implied, so --all-images alone is meaningful.
        assert!(parse_sync_images_args(&args(&["--stage-only", "--all-images"])).unwrap().validate().is_ok());
    }

    #[test]
    fn refused_combinations_say_why() {
        for (tail, needle) in [
            (&["--all-images", "host8"][..], "controller-only"),
            (&["--arch", "amd64", "host8"][..], "own architecture"),
            (&["--lock"][..], "nothing would pull"),
            (&["--stage-only", "host8"][..], "takes no nodes"),
            (&["--stage-only", "--all"][..], "takes no nodes"),
            (&["--stage-only", "--no-restart"][..], "no pull"),
            (&["--stage-only", "-i", "x", "--all-images"][..], "add --lock"),
        ] {
            let why = parse_sync_images_args(&args(tail)).unwrap().validate().unwrap_err();
            assert!(why.contains(needle), "{tail:?}: {why}");
        }
    }

    #[test]
    fn bare_node_defaults_to_restart_and_empty_image_list() {
        let a = parse_sync_images_args(&args(&["host8"])).unwrap();
        assert_eq!(a.nodes, vec!["host8"]);
        assert!(a.images.is_empty(), "no flag = default set decided later, not here");
        assert!(a.restart, "restart is the default");
        assert!(!a.all);
    }

    #[test]
    fn image_flag_repeats() {
        let a = parse_sync_images_args(&args(&["host8", "-i", "node-agent", "--image", "llamacpp"])).unwrap();
        assert_eq!(a.images, vec!["node-agent", "llamacpp"]);
    }

    #[test]
    fn images_csv_splits_trims_and_drops_empties() {
        let a = parse_sync_images_args(&args(&["host8", "--images", " a , b ,,c, "])).unwrap();
        assert_eq!(a.images, vec!["a", "b", "c"]);
    }

    #[test]
    fn image_and_images_combine_in_argument_order() {
        let a = parse_sync_images_args(&args(&["-i", "x", "--images", "y,z", "host8"])).unwrap();
        assert_eq!(a.images, vec!["x", "y", "z"]);
        assert_eq!(a.nodes, vec!["host8"]);
    }

    #[test]
    fn last_restart_flag_wins() {
        assert!(!parse_sync_images_args(&args(&["n", "--no-restart"])).unwrap().restart);
        assert!(parse_sync_images_args(&args(&["n", "--no-restart", "--restart"])).unwrap().restart);
    }

    #[test]
    fn all_flag_parses() {
        let a = parse_sync_images_args(&args(&["--all"])).unwrap();
        assert!(a.all);
        assert!(a.nodes.is_empty());
    }

    /// `-u/--user` named an SSH account. It went with the SSH lane, and a
    /// flag that silently does nothing is worse than one that is gone.
    #[test]
    fn the_retired_ssh_user_flag_is_refused_not_ignored() {
        assert!(parse_sync_images_args(&args(&["host8", "-u", "youruser"])).is_err());
        assert!(parse_sync_images_args(&args(&["host8", "--user", "youruser"])).is_err());
    }

    #[test]
    fn unknown_flag_is_unhandled_not_a_node_name() {
        assert!(parse_sync_images_args(&args(&["--frobnicate"])).is_err());
    }

    #[test]
    fn flags_missing_their_value_are_unhandled() {
        for tail in [&["-i"][..], &["--image"], &["--images"]] {
            assert!(parse_sync_images_args(&args(tail)).is_err(), "{tail:?}");
        }
    }

    // ── image-list handling ──

    #[test]
    fn duplicate_images_ship_once_first_position_kept() {
        let d = dedupe_images(args(&["a", "b", "a", "c", "b"]));
        assert_eq!(d, vec!["a", "b", "c"]);
    }

    #[test]
    fn default_set_is_the_worker_relevant_controller_builds() {
        let d = default_sync_images();
        assert!(d.iter().any(|i| i.contains("node-agent")));
        assert!(d.iter().any(|i| i.contains("noo-sandbox-base")));
    }

    // ── same-ID skip ──

    #[test]
    fn tar_names_match_the_go_convention() {
        use crate::commands::image_stage::image_tar_name;
        // The convention IS the protocol: the Go half (ImageTarName in the
        // node-agent's internal/docker) pins the SAME cases — if either
        // side changes, its twin test must change with it.
        assert_eq!(
            image_tar_name("pai-assistant/node-agent:latest", "amd64"),
            "pai-assistant_node-agent_latest_amd64.tar"
        );
        assert_eq!(image_tar_name("noo-sandbox-base:latest", "arm64"), "noo-sandbox-base_latest_arm64.tar");
        assert_eq!(
            image_tar_name("ghcr.io/noomesh/llamacpp:v0.1.47", "amd64"),
            "ghcr.io_noomesh_llamacpp_v0.1.47_amd64.tar"
        );
        // The result must pass the gateway's valid_artifact_name rules: no
        // '/', no leading dot, ends .tar.
        for name in [
            image_tar_name("pai-assistant/node-agent:latest", "amd64"),
            image_tar_name("ghcr.io/x/y:z", "arm64"),
        ] {
            assert!(!name.contains('/') && !name.starts_with('.') && name.ends_with(".tar"), "{name}");
        }
    }

    // ── node resolution ──

    #[test]
    fn gateway_record_wins_over_inventory_row() {
        let gw = vec![json!({"id": "host8", "hostname": "host8", "ip_address": "192.0.2.69"})];
        let inv = vec![("host8".to_string(), "10.0.0.9".to_string(), "youruser".to_string())];
        let n = resolve_sync_node(&gw, &inv, "host8").unwrap();
        assert_eq!(n["ip_address"].as_str(), Some("192.0.2.69"));
        assert!(n["source"].is_null(), "gateway records are not tagged as inventory");
    }

    #[test]
    fn inventory_row_answers_when_gateway_does_not_know_the_node() {
        let inv = vec![("host9".to_string(), "192.0.2.70".to_string(), "youruser".to_string())];
        let n = resolve_sync_node(&[], &inv, "host9").unwrap();
        assert_eq!(n["ip_address"].as_str(), Some("192.0.2.70"));
        assert_eq!(n["ssh_user"].as_str(), Some("youruser"));
        assert_eq!(n["source"].as_str(), Some("inventory"));
    }

    #[test]
    fn hostname_matches_gateway_records_too() {
        let gw = vec![json!({"id": "node-1", "hostname": "host8", "ip_address": "192.0.2.69"})];
        assert!(resolve_sync_node(&gw, &[], "host8").is_some());
        assert!(resolve_sync_node(&gw, &[], "nope").is_none());
    }
}

// ═══ fu73: the applier-evolution lanes — hostd/applier/backends over the rail ═══

/// Shared skeleton: build a signed one-kind bundle and deliver it to each
/// node pull-first (gate fallback), reporting per-node outcomes honestly.
/// Delivery proves COLLECTION; for these kinds the node-side applier is the
/// verifier (it reverts a bad hostd itself and refuses unknown kinds loudly
/// with exit 76) — the report says exactly that instead of claiming applied
/// (the #83 lesson: fetched ≠ applied).
pub(crate) fn deliver_kind_to_nodes(
    g: &Globals,
    nodes: &[String],
    kind: &'static str,
    payload_for: &dyn Fn(&str) -> Result<Vec<u8>, String>,
    acceptance_hint: &str,
) -> Result<i32, Unhandled> {
    deliver_kind_to_nodes_then(g, nodes, kind, payload_for, acceptance_hint, None)
}

/// A per-node gate: `Ok(note)` lets the roll continue, `Err` stops it.
pub(crate) type AfterOk<'a> = &'a dyn Fn(&str, &crate::commands::security_local::CertDelivery) -> Result<String, String>;

/// [`deliver_kind_to_nodes`] with a per-node gate: `after_ok(node, delivery)` runs once
/// a node's delivery succeeded (or, `FetchedUnconfirmed`: the node collected the
/// bundle but its apply report never arrived, so the gate is the only judge and
/// an `Ok` from it IS the success, labelled by its own note), BEFORE the next node is touched. `Ok(note)`
/// is appended to that node's outcome line; `Err` fails the node AND stops
/// the roll (the remaining nodes are reported "not attempted"), so a bundle
/// that restarts something on the node (host-telemetry restarts tailscaled)
/// never rolls on past a node that did not come back.
pub(crate) fn deliver_kind_to_nodes_then(
    g: &Globals,
    nodes: &[String],
    kind: &'static str,
    payload_for: &dyn Fn(&str) -> Result<Vec<u8>, String>,
    acceptance_hint: &str,
    after_ok: Option<AfterOk>,
) -> Result<i32, Unhandled> {
    let ca = crate::pki::ClusterCa::new(crate::pki::pki_dir());
    if !ca.ca_exists() {
        fail(g.json, ExitCode::Generic, "no_ca", "no cluster CA — run 'noo onboard' first", None);
    }
    let mut results: Vec<(String, String, bool)> = Vec::new();
    // Every node's state visible at once, rather than whichever is first.
    // Off a TTY this prints one line per transition, so a log reads the
    // same; under --json it prints nothing and the envelope below is the
    // whole output.
    let mut live = (!g.json).then(|| ui::Live::new(nodes.to_vec()));
    if let Some(l) = live.as_mut() {
        for (i, _) in nodes.iter().enumerate() {
            l.set(i, &ui::muted("waiting"));
        }
    }
    for (idx, node) in nodes.iter().enumerate() {
        if let Some(l) = live.as_mut() {
            l.set(idx, &ui::status_line(Glyph::Step, "delivering"));
        }
        let outcome = (|| -> Result<crate::commands::security_local::CertDelivery, String> {
            let payload = payload_for(node)?;
            let work = std::env::temp_dir()
                .join(format!("noo-{kind}-{}-{}", node, std::process::id()));
            std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
            let files: Vec<(&str, Vec<u8>)> = vec![(kind, payload)];
            let bundle = crate::commands::security_local::build_signed_bundle(&ca, node, &files, &work)?;
            let d = crate::commands::security_local::deliver_signed_bundle(g, node, &bundle, &work, None);
            let _ = std::fs::remove_dir_all(&work);
            Ok(d)
        })();
        let (label, ok, delivery) = match outcome {
            Ok(d) => {
                let ok = d.ok();
                // Collected is honest but partial for non-cert kinds: the
                // applier is the judge from here (revert-on-bad-hostd,
                // exit-76 on an applier that predates the kind).
                let label = match &d {
                    // Collected = the node fetched it but has never reported an
                    // apply (an agent/fetcher too old to). Nothing here shows the
                    // kind took — an old applier may have skipped it — so say so
                    // instead of passing for a success.
                    crate::commands::security_local::CertDelivery::Collected =>
                        format!("collected, NOT confirmed — this node has never reported an apply, so an old applier \
                                 could have skipped the kind; check the effect, or `noo cluster upgrade-applier {node}` \
                                 ({acceptance_hint})"),
                    crate::commands::security_local::CertDelivery::Verified =>
                        format!("collected — node-side apply is the verdict from here ({acceptance_hint})"),
                    // Applied already IS the node-side verdict (noo-apply
                    // reported exit 0 for this exact bundle), so it keeps
                    // its own label rather than deferring to a judge that
                    // has already spoken.
                    other => other.label(),
                };
                (label, ok, Some(d))
            }
            Err(e) => (format!("UNDELIVERED — {e}"), false, None),
        };
        // The gate runs on a success, and ALSO on a bundle the node fetched
        // whose apply report never arrived: that is not "not fetched" and not
        // a success, it is unproven, and the gate (the node's own heartbeat,
        // for host-telemetry) is the judge. Its `Ok` there replaces the
        // unconfirmed label — the effect was observed — and its `Err` keeps it.
        let unconfirmed = matches!(
            delivery,
            Some(crate::commands::security_local::CertDelivery::FetchedUnconfirmed)
        );
        let (label, ok) = match (ok || unconfirmed, after_ok, delivery.as_ref()) {
            (true, Some(gate), Some(d)) => match gate(node, d) {
                Ok(note) if unconfirmed => (note, true),
                Ok(note) => (format!("{label}; {note}"), true),
                Err(e) => (format!("{label}; {e}"), false),
            },
            _ => (label, ok),
        };
        if let Some(l) = live.as_mut() {
            let glyph = if ok { Glyph::Ok } else { Glyph::Err };
            l.set(idx, &ui::status_line(glyph, &label));
        }
        results.push((node.clone(), label, ok));
        if !ok && after_ok.is_some() {
            for (j, rest) in nodes.iter().enumerate().skip(idx + 1) {
                let why = format!("not attempted — the roll stopped at {node}");
                if let Some(l) = live.as_mut() {
                    l.set(j, &ui::status_line(Glyph::Err, &why));
                }
                results.push((rest.clone(), why, false));
            }
            break;
        }
    }
    if let Some(l) = live.take() {
        l.finish();
    }
    let failed = results.iter().filter(|(_, _, ok)| !ok).count();
    if !g.json && nodes.len() > 1 {
        // A real denominator, so a bar is honest here: every node has
        // reported. Never shown for a single node, where it says nothing
        // the outcome line does not.
        say(&format!("  {}", ui::bar(results.len() - failed, results.len(), 20)));
    }
    if g.json {
        println!("{}", serde_json::json!({
            "kind": kind,
            "results": results.iter().map(|(n, l, ok)| serde_json::json!({
                "node": n, "ok": ok, "detail": l })).collect::<Vec<_>>(),
        }));
    } else if failed > 0 {
        ui::close_warned(&format!("{failed} node(s) did not take the {kind} bundle"));
    } else {
        ui::close_done(&format!("{kind} bundle delivered to {} node(s)", results.len()));
    }
    Ok(if failed > 0 { 1 } else { 0 })
}

/// `noo cluster upgrade-hostd NODE... [--skip-build] [--yes]` — roll the
/// confined-root host daemon over the pull rail (fu73). `noo cluster verify
/// <node>` afterwards is the acceptance test (the agent swap this used to
/// precede was retired by an earlier release). Nodes whose applier
/// predates the hostd-binary kind refuse with exit 76 — converge them once
/// (re-run the enrollment paste, or `noo cluster upgrade-applier` after
/// their applier is current).
pub fn cluster_upgrade_hostd(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut nodes: Vec<String> = Vec::new();
    let mut yes = false;
    let mut skip_build = false;
    for tok in args {
        match tok.as_str() {
            "--force" | "--yes" | "-y" => yes = true,
            "--skip-build" => skip_build = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => nodes.push(t.to_string()),
        }
    }
    if nodes.is_empty() {
        fail(g.json, ExitCode::Generic, "no_nodes",
            "name the node(s) to roll: noo cluster upgrade-hostd <node> [<node>…]",
            Some("hostd rolls are deliberate and serial — no implicit fleet-wide default"));
    }

    // Arch per node from the registry; unknown builds both (over-building
    // is cheap).
    let doc = crate::http::get_json(g, "/api/cluster/nodes", true, 10);
    let empty = Vec::new();
    let known = doc["nodes"].as_array().unwrap_or(&empty);
    let mut arches: Vec<&'static str> = Vec::new();
    let mut node_arch: Vec<(String, Option<NodeArch>)> = Vec::new();
    for node in &nodes {
        let entry = known.iter().find(|n| {
            n.get("id").and_then(|v| v.as_str())
                .or_else(|| n.get("node_id").and_then(|v| v.as_str()))
                .or_else(|| n.get("name").and_then(|v| v.as_str()))
                .is_some_and(|id| id.eq_ignore_ascii_case(node))
        });
        let arch = entry.and_then(|n| node_arch_signal(n).map(|(a, _)| a));
        match arch {
            Some(NodeArch::Arm) => arches.push("arm64"),
            Some(_) => arches.push("amd64"),
            None => arches.extend(["amd64", "arm64"]),
        }
        node_arch.push((node.clone(), arch));
    }
    arches.sort_unstable();
    arches.dedup();
    super::confirm_destructive(g, yes, "roll noo-hostd on", &nodes.join(", "));

    if !skip_build && !repo_root().join("node-agent-go").join("build-cross.sh").is_file() {
        fail(g.json, ExitCode::Generic, "not_checkout",
            &format!("cross-building noo-hostd needs the source checkout (node-agent-go/build-cross.sh \
                      is not under {}) — a binary-installed controller has no tree to build from",
                     repo_root().display()),
            Some("run this from a checkout, or pass --skip-build with prebuilt node-agent-go/noo-hostd-<arch> binaries"));
    }
    if !skip_build {
        if !g.json {
            say(&ui::phase("Build"));
        }
        for arch in &arches {
            if !g.json {
                ui::step(&format!("cross-building noo-hostd for {arch}"));
            }
            let rc = Command::new(repo_root().join("node-agent-go").join("build-cross.sh"))
                .arg(arch)
                .env("BINARY", "noo-hostd")
                .status()
                .map(|s| s.code().unwrap_or(1))
                .unwrap_or(1);
            if rc != 0 {
                fail(g.json, ExitCode::Generic, "build_failed",
                    &format!("cross-build noo-hostd for {arch} failed — aborting before touching any node"), None);
            }
            if !g.json {
                ui::done(&format!("noo-hostd built for {arch}"));
            }
        }
    }
    if !g.json {
        say(&ui::phase("Deliver"));
    }

    let payload = move |node: &str| -> Result<Vec<u8>, String> {
        let arch = node_arch
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(node))
            .and_then(|(_, a)| *a);
        let goarch = match arch {
            Some(NodeArch::Arm) => "arm64",
            Some(_) => "amd64",
            None => return Err(
                "arch unknown for this node — pass an arch-known registered node, or build \
                 and deliver by hand".into()),
        };
        std::fs::read(repo_root().join("node-agent-go").join(format!("noo-hostd-{goarch}")))
            .map_err(|e| format!("built binary missing ({e}) — did the cross-build run?"))
    };
    deliver_kind_to_nodes(g, &nodes, "hostd-binary", &payload,
        "the applier keeps .prev and reverts a hostd with no fresh heartbeat; \
         acceptance: noo cluster verify <node>")
}

/// `noo cluster upgrade-applier NODE... [--yes]` — ship the current
/// noo-apply over the rail. Nodes whose applier already knows the `applier`
/// kind take it and self-swap; older appliers refuse with exit 76 (loud in
/// their journal), fixed by one attended converge (re-run the enrollment
/// paste — idempotent), after which applier updates ride the rail forever.
pub fn cluster_upgrade_applier(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut nodes: Vec<String> = Vec::new();
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            "--force" | "--yes" | "-y" => yes = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => nodes.push(t.to_string()),
        }
    }
    if nodes.is_empty() {
        return Err(Unhandled);
    }
    // A Mac's applier is the noo CLI (`noo node fetch`), not noo-apply.sh;
    // rolling the shell script to it stages a bundle nothing will use (it sat
    // "STAGED only" on host6, 2026-10-06). Skip those, and do not count them
    // as failures.
    let (nodes, macs) = split_mac_nodes(nodes, &|n| {
        super::provision::enrolled_os(super::provision::redemption_record(g, n).as_ref()) == "macos"
    });
    for n in &macs {
        if !g.json { println!("{}", ui::note(&mac_applier_skip_line(n))); }
    }
    if nodes.is_empty() {
        return Ok(0);
    }
    super::confirm_destructive(g, yes, "roll noo-apply on", &nodes.join(", "));
    let payload = move |_node: &str| -> Result<Vec<u8>, String> { applier_payload() };
    deliver_kind_to_nodes(g, &nodes, "applier", &payload,
        "an old applier refuses the kind with exit 76 in the node journal — \
         converge it once with the enrollment paste")
}

/// Partition `nodes` into (non-Mac, Mac), keeping order.
fn split_mac_nodes(nodes: Vec<String>, is_mac: &dyn Fn(&str) -> bool) -> (Vec<String>, Vec<String>) {
    nodes.into_iter().partition(|n| !is_mac(n))
}

fn mac_applier_skip_line(node: &str) -> String {
    format!("{node}: macOS — its applier is the noo CLI, which `noo upgrade --all` / `noo cluster provision {node}` updates; nothing to roll")
}

/// The applier this CLI ships, as `upgrade-applier` delivers it.
///
/// The released binary carries noo-apply.sh compiled in (build.rs
/// ENROLL_ASSETS, `ASSET_APPLY`). That copy is the one to roll: a dist
/// controller has no source tree, and `repo_root()/scripts/noo-apply.sh`
/// does not exist there. Reading the tree made `noo cluster upgrade-applier`
/// fail on every dist controller with "read noo-apply.sh: No such file or
/// directory" (host8, v0.2.91, 2026-10-04), the same trap the harness unit
/// hit on 2026-09-19. Only a crate-only build (empty asset) falls back to
/// the tree.
fn applier_payload() -> Result<Vec<u8>, String> {
    let embedded = super::enroll::asset_apply();
    if !embedded.is_empty() {
        return Ok(embedded.as_bytes().to_vec());
    }
    let script = repo_root().join("scripts").join("noo-apply.sh");
    std::fs::read(&script).map_err(|e| format!("read noo-apply.sh: {e} (this noo was built without the embedded applier)"))
}

/// `noo cluster restart-backends NODE SVC... [--yes]` — rail-driven restart
/// of node-side backend containers (fu72 #3's missing half: after a cert
/// change NOTHING restarted a worker's vllm, and it served plain HTTP
/// silently on 2026-08-20). Services must be noo-* container names.
pub fn cluster_restart_backends(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positional: Vec<String> = Vec::new();
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            "--force" | "--yes" | "-y" => yes = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => positional.push(t.to_string()),
        }
    }
    if positional.len() < 2 {
        return Err(Unhandled);
    }
    let node = positional.remove(0);
    for svc in &positional {
        if !svc.starts_with("noo-") || !svc.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            fail(g.json, ExitCode::Generic, "bad_service",
                &format!("'{svc}' is not a noo-* container name"), None);
        }
    }
    super::confirm_destructive(g, yes, "restart backends on", &node);
    let list = positional.join("\n") + "\n";
    let payload = move |_node: &str| -> Result<Vec<u8>, String> { Ok(list.clone().into_bytes()) };
    deliver_kind_to_nodes(g, std::slice::from_ref(&node), "restart-backends", &payload,
        "restarts are logged in the node journal (tag noo-apply)")
}

#[cfg(test)]
mod applier_payload_tests {
    #[test]
    fn upgrade_applier_rolls_the_embedded_applier_not_a_file_on_disk() {
        let embedded = super::super::enroll::asset_apply();
        if embedded.is_empty() {
            eprintln!("crate-only build (no embedded applier) — skipped");
            return;
        }
        let got = super::applier_payload().expect("payload");
        assert_eq!(got, embedded.as_bytes(), "upgrade-applier must deliver the applier compiled into this binary");
        assert!(String::from_utf8_lossy(&got).contains("KNOWN_KINDS"), "that is noo-apply.sh");
    }

    #[test]
    fn upgrade_applier_skips_macs_and_says_why() {
        let nodes = vec!["host8".to_string(), "host6".to_string(), "pi".to_string()];
        let (rest, macs) = super::split_mac_nodes(nodes, &|n| n == "host6");
        assert_eq!(rest, vec!["host8", "pi"]);
        assert_eq!(macs, vec!["host6"]);
        let line = super::mac_applier_skip_line("host6");
        assert!(line.starts_with("host6: macOS"), "{line}");
        assert!(line.contains("noo upgrade --all") && line.contains("noo cluster provision host6"), "{line}");
        let (rest, macs) = super::split_mac_nodes(vec!["host6".into()], &|_| true);
        assert!(rest.is_empty() && macs.len() == 1, "an all-Mac request has nothing left to roll");
    }
}
