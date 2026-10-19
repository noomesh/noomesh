// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noomesh.yaml` edits — coordinator backend/model, cloud providers,
//! watched folders, and workspace. Faithful to `onboard/helpers.py`'s
//! `_update_yaml_config` / `_update_yaml_workspace` / `_update_yaml_user_dirs`
//! and `step_model._enable_cloud_config`, using serde_yaml round-tripping
//! (like Python's `yaml.safe_load` / `yaml.dump(sort_keys=False)`; comments are
//! not preserved by either). Non-fatal: any error is swallowed, matching the
//! Python steps' bare `except: pass`.

use std::path::PathBuf;

use serde_yaml::{Mapping, Value};

use super::Ctx;

/// `noomesh.yaml` is the only config file; returns None when it does not
/// exist (nothing to update). The `pai-assistant.yaml` fallback was retired
/// 2026-08-02 — it had drifted to a different model and silently supplied
/// stale values.
fn config_path(ctx: &Ctx) -> Option<PathBuf> {
    let a = ctx.repo_root.join("noomesh.yaml");
    if a.exists() {
        return Some(a);
    }
    None
}

fn load(path: &PathBuf) -> Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_yaml::from_str::<Value>(&t).ok())
        .filter(|v| v.is_mapping())
        .unwrap_or_else(|| Value::Mapping(Mapping::new()))
}

/// Is this file safe to round-trip through serde_yaml?
///
/// Every writer here is load → mutate → write-whole. `load` answers "empty
/// mapping" for a file it cannot parse, so a `noomesh.yaml` with one bad
/// hand-edit — a stray tab, an unquoted `@` — was not left alone: the next
/// `noo onboard` replaced the operator's entire runtime config with a
/// document containing only the key that step happened to set. Pure config
/// loss, silently, from a wizard whose contract is "existing settings are
/// preserved". An unreadable file is a REFUSAL, not a blank slate.
///
/// A file that does not exist is a different thing entirely: `config_path`
/// has already returned None for it, and nothing reaches here.
fn parses(path: &PathBuf) -> bool {
    match std::fs::read_to_string(path) {
        Ok(t) if t.trim().is_empty() => true,
        Ok(t) => serde_yaml::from_str::<Value>(&t).map(|v| v.is_mapping()).unwrap_or(false),
        // Unreadable is not "empty" either — refuse for the same reason.
        Err(_) => false,
    }
}

fn save(ctx: &Ctx, path: &PathBuf, value: &Value) {
    if ctx.dry_run {
        ctx.dry(&format!("update {}", path.display()));
        return;
    }
    if !parses(path) {
        ctx.warn(&format!(
            "{} is not readable as a YAML mapping — NOT rewriting it (the whole file would \
             be replaced by this one setting). Fix the file, then: noo onboard --only <section>",
            path.display()
        ));
        return;
    }
    if let Ok(text) = serde_yaml::to_string(value) {
        let _ = std::fs::write(path, text);
    }
}

fn key(s: &str) -> Value {
    Value::String(s.to_string())
}

fn map_mut<'a>(v: &'a mut Value, k: &str) -> &'a mut Value {
    let m = v.as_mapping_mut().expect("mapping");
    if !m.contains_key(key(k)) {
        m.insert(key(k), Value::Mapping(Mapping::new()));
    }
    m.get_mut(key(k)).unwrap()
}

/// `cluster.default_backend = backend`, `cluster.backends.<backend>.{enabled=true,
/// model=...}`, and disable the other inference backend. Parity with
/// `_update_yaml_config`.
///
/// The model recorded here is the LOCAL backend's placement hint (what this
/// box pulls and serves, and the static `OLLAMA_URL` last resort's model).
/// It is not a routing pin: the gateway sends unpinned chat to every live
/// chat node (`chat-default` dynamic) and logs once that the yaml value is
/// a hint. Existing yamls with `default_backend: ollama` + a model keep
/// working unchanged — the value simply stops narrowing the default.
pub fn update_yaml_config(ctx: &Ctx, backend: &str, model: &str) {
    let Some(path) = config_path(ctx) else { return };
    let mut data = load(&path);
    {
        let cluster = map_mut(&mut data, "cluster");
        cluster
            .as_mapping_mut()
            .unwrap()
            .insert(key("default_backend"), key(backend));
        let backends = map_mut(cluster, "backends");
        let bcfg = map_mut(backends, backend);
        let bm = bcfg.as_mapping_mut().unwrap();
        bm.insert(key("enabled"), Value::Bool(true));
        bm.insert(key("model"), key(model));
        let other = if backend == "vllm" { "ollama" } else { "vllm" };
        if let Some(o) = backends.as_mapping_mut().unwrap().get_mut(key(other)) {
            if let Some(om) = o.as_mapping_mut() {
                om.insert(key("enabled"), Value::Bool(false));
            }
        }
    }
    save(ctx, &path, &data);
}

/// `services.gateway_url` = the advertised self URL. The example seeds it as
/// `https://localhost:8080`, and nothing rewrote it until now — but enrollment
/// blobs embed this value (`routes/bootstrap.rs`), so a localhost value
/// poisons every node join. `heartbeat.gateway_url` is NOT touched: that one
/// is deliberately loopback (the scheduler self-calls the gateway).
pub fn update_yaml_gateway_url(ctx: &Ctx, url: &str) {
    let Some(path) = config_path(ctx) else { return };
    let mut data = load(&path);
    {
        let services = map_mut(&mut data, "services");
        services
            .as_mapping_mut()
            .unwrap()
            .insert(key("gateway_url"), key(url));
    }
    save(ctx, &path, &data);
}

/// Enable `cloud_providers` with a default provider (parity with `_enable_cloud_config`).
pub fn enable_cloud_config(ctx: &Ctx, provider: &str) {
    let Some(path) = config_path(ctx) else { return };
    let mut data = load(&path);
    {
        let cloud = map_mut(&mut data, "cloud_providers");
        let cm = cloud.as_mapping_mut().unwrap();
        cm.insert(key("enabled"), Value::Bool(true));
        cm.insert(key("default_provider"), key(provider));
        if !cm.contains_key(key("fallback_order")) {
            cm.insert(
                key("fallback_order"),
                Value::Sequence(vec![key("anthropic"), key("openai"), key("google")]),
            );
        }
    }
    save(ctx, &path, &data);
}

/// `watched_folders.folders` = `[{host,mount}]`, `watched_folders.enabled`, and
/// `tools.allowed_paths` = container mounts. Parity with `_update_yaml_user_dirs`.
pub fn update_yaml_user_dirs(ctx: &Ctx, entries: &[(String, String)]) {
    let Some(path) = config_path(ctx) else { return };
    let mut data = load(&path);
    {
        let wf = map_mut(&mut data, "watched_folders");
        let wfm = wf.as_mapping_mut().unwrap();
        wfm.insert(key("enabled"), Value::Bool(!entries.is_empty()));
        let folders: Vec<Value> = entries
            .iter()
            .map(|(h, m)| {
                let mut fm = Mapping::new();
                fm.insert(key("host"), key(h));
                fm.insert(key("mount"), key(m));
                Value::Mapping(fm)
            })
            .collect();
        wfm.insert(key("folders"), Value::Sequence(folders));

        let tools = map_mut(&mut data, "tools");
        let allowed: Vec<Value> = entries.iter().map(|(_, m)| key(m)).collect();
        tools
            .as_mapping_mut()
            .unwrap()
            .insert(key("allowed_paths"), Value::Sequence(allowed));
    }
    save(ctx, &path, &data);
}

/// Previously configured shared Drive ids `[(drive_id, label)]` — the
/// reconfigure default, empty when the section is absent or disabled.
pub fn read_yaml_watched_drives(ctx: &Ctx) -> Vec<(String, String)> {
    let Some(path) = config_path(ctx) else { return Vec::new() };
    let data = load(&path);
    let Some(wd) = data.get("watched_drives") else { return Vec::new() };
    if wd.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
        return Vec::new();
    }
    wd.get("drives")
        .and_then(|d| d.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|d| {
                    let id = d.get("drive_id")?.as_str()?.to_string();
                    let label = d.get("label").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    Some((id, label))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `watched_drives.drives` = `[{drive_id,label}]` + `watched_drives.enabled`.
/// Other keys in the section (batch size, notify targets) are preserved —
/// this only owns the drive list. Drive ids are host-independent, unlike
/// `watched_folders`, so a fresh walk can carry them without re-pointing.
pub fn update_yaml_watched_drives(ctx: &Ctx, drives: &[(String, String)]) {
    let Some(path) = config_path(ctx) else { return };
    let mut data = load(&path);
    {
        let wd = map_mut(&mut data, "watched_drives");
        let wdm = wd.as_mapping_mut().unwrap();
        wdm.insert(key("enabled"), Value::Bool(!drives.is_empty()));
        let list: Vec<Value> = drives
            .iter()
            .map(|(id, label)| {
                let mut m = Mapping::new();
                m.insert(key("drive_id"), key(id));
                m.insert(key("label"), key(label));
                Value::Mapping(m)
            })
            .collect();
        wdm.insert(key("drives"), Value::Sequence(list));
    }
    save(ctx, &path, &data);
}

/// One key of the flat `compose_env:` map (the compose-interpolated,
/// non-secret plane — see CLAUDE.md "WHERE DOES THIS VALUE GO?").
pub fn read_yaml_compose_env(ctx: &Ctx, k: &str) -> Option<String> {
    let path = config_path(ctx)?;
    let data = load(&path);
    data.get("compose_env")?.get(k)?.as_str().map(str::to_string)
}

/// Upsert keys into `compose_env:` — the launcher exports this map before
/// compose runs, so the gateway sees them on its next (re)create.
pub fn update_yaml_compose_env(ctx: &Ctx, pairs: &[(String, String)]) {
    let Some(path) = config_path(ctx) else { return };
    let mut data = load(&path);
    {
        let ce = map_mut(&mut data, "compose_env");
        let m = ce.as_mapping_mut().unwrap();
        for (k, v) in pairs {
            m.insert(key(k), key(v));
        }
    }
    save(ctx, &path, &data);
}

/// Previously configured workspace host path, if any — the reconfigure
/// default (first-contact finding #23: re-runs forgot the workspace).
pub fn read_yaml_workspace(ctx: &Ctx) -> Option<String> {
    let path = config_path(ctx)?;
    let data = load(&path);
    let ws = data.get("workspace")?;
    if ws.get("enabled").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    ws.get("host").and_then(|v| v.as_str()).map(str::to_string)
}

/// `workspace = {enabled, host, mount}` + append the mount to `tools.allowed_paths`.
/// Parity with `_update_yaml_workspace`.
pub fn update_yaml_workspace(ctx: &Ctx, host: &str, container: &str) {
    let Some(path) = config_path(ctx) else { return };
    let mut data = load(&path);
    {
        let m = data.as_mapping_mut().unwrap();
        let mut ws = Mapping::new();
        ws.insert(key("enabled"), Value::Bool(true));
        ws.insert(key("host"), key(host));
        ws.insert(key("mount"), key(container));
        m.insert(key("workspace"), Value::Mapping(ws));

        let tools = map_mut(&mut data, "tools");
        let tm = tools.as_mapping_mut().unwrap();
        let list = tm
            .entry(key("allowed_paths"))
            .or_insert_with(|| Value::Sequence(Vec::new()));
        if let Some(seq) = list.as_sequence_mut() {
            if !seq.iter().any(|v| v.as_str() == Some(container)) {
                seq.push(key(container));
            }
        }
    }
    save(ctx, &path, &data);
}

/// Read the `addons:` map — the ONE place an add-on's on/off state lives.
///
/// `None` for a name means "not stated", which the gateway resolves to that
/// add-on's own polarity. That is a different answer from `Some(false)` and
/// the wizard has to keep them apart: re-running onboard must be able to show
/// "you have not chosen yet" rather than pre-answering with `off`.
pub fn read_yaml_addon(ctx: &Ctx, name: &str) -> Option<bool> {
    let path = config_path(ctx)?;
    let data = load(&path);
    data.get("addons")?.get(name)?.as_bool()
}

/// Upsert one add-on into `addons:`.
pub fn update_yaml_addon(ctx: &Ctx, name: &str, on: bool) {
    let Some(path) = config_path(ctx) else { return };
    let mut data = load(&path);
    {
        let addons = map_mut(&mut data, "addons");
        let m = addons.as_mapping_mut().unwrap();
        m.insert(key(name), Value::Bool(on));
    }
    save(ctx, &path, &data);
}

#[cfg(test)]
mod tests {
    use super::parses;

    /// Every writer here is load → mutate → write-whole, and `load` answers
    /// "empty mapping" for a file it cannot parse. Without this guard the
    /// next `noo onboard` replaces an operator's whole `noomesh.yaml` with
    /// the one key that step happened to set.
    #[test]
    fn an_unparseable_config_is_refused_not_replaced() {
        let dir = std::env::temp_dir().join(format!("noo-yamlcfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("noomesh.yaml");

        // The happy path must SAY YES, or the guard is just a global refusal
        // and the fixture below proves nothing.
        std::fs::write(&p, "compose_env:\n  HF_CACHE_DIR: /srv/hf\nsecurity: {}\n").unwrap();
        assert!(parses(&p), "a valid mapping must remain writable");

        // A hand-edit that serde_yaml cannot read. Duplicate keys are the
        // real-world shape (an operator appending a second `compose_env:`).
        std::fs::write(&p, "compose_env:\n  A: 1\ncompose_env:\n  B: 2\n").unwrap();
        assert!(!parses(&p), "a file serde_yaml cannot round-trip must be refused");

        // A scalar document is not a mapping — writing would drop it too.
        std::fs::write(&p, "just-a-string\n").unwrap();
        assert!(!parses(&p));

        // An EMPTY file is genuinely a blank slate; seeding it is correct.
        std::fs::write(&p, "\n").unwrap();
        assert!(parses(&p));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
