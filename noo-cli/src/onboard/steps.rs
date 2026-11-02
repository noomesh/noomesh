// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The eight wizard steps (7 doing work + a summary rendered by mod.rs).
//! Each is a faithful port of the matching `onboard/step_*.py`.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::prompt::Prompt;
use super::{env, sh, util, yamlcfg, Ctx, SECRETS, STATE_SUBDIRS, STORAGE_SUBDIRS};
use crate::envfile::ENROLLED_CONTROLLER_URL;
use crate::pki::{ClusterCa, DEFAULT_DAYS};

// ── Step 1: Prerequisites ────────────────────────────────────────────────

/// Finding #65: install.sh ships whatever version its release URL pointed at,
/// and a fresh box has no habit of running `noo upgrade` — the wizard's first
/// step is the one reliable place to notice a newer CLI exists. Best-effort
/// and quiet on failure (an offline install must not stall or nag);
/// interactive consoles get an offer, headless runs get a one-line note.
fn offer_self_upgrade(ctx: &mut Ctx) {
    if ctx.dry_run {
        return;
    }
    let current = env!("CARGO_PKG_VERSION");
    let latest = match crate::commands::upgrade::resolve_latest(ctx.g) {
        Ok(v) => v,
        Err(e) => {
            if ctx.g.verbose {
                ctx.info(&format!("(release check skipped: {e})"));
            }
            return;
        }
    };
    if latest == current {
        return;
    }
    ctx.warn(&format!("noo {current} installed; {latest} is available"));
    if ctx.non_interactive || !ctx.ui.inherit_stdio() || !super::prompt::stdin_is_tty() {
        ctx.info("(upgrade later with: noo upgrade)");
        return;
    }
    if !ctx.asker.confirm("Upgrade the CLI before onboarding? (recommended)", true) {
        return;
    }
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "noo".into());
    let ok = Command::new(&exe).arg("upgrade").status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        ctx.warn("upgrade failed — continuing on the current version (retry later: noo upgrade)");
        return;
    }
    // The swap replaced the binary on disk, but THIS process is still the old
    // build — relaunch the wizard through the path with the original argv so
    // the new version runs it (same trick as the docker-group relaunch).
    ctx.progress(&format!("Relaunching the wizard on noo {latest}..."));
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match Command::new(&exe).args(&argv).status().ok().and_then(|s| s.code()) {
        Some(c) => std::process::exit(c),
        None => ctx.warn("relaunch failed — re-run `noo onboard` to use the new version"),
    }
}

pub fn prerequisites(ctx: &mut Ctx) -> bool {
    offer_self_upgrade(ctx);
    let mut all_ok = true;
    let mut missing_apt: Vec<&str> = Vec::new(); // plain apt packages
    let mut docker_missing = false;

    for (tool, purpose) in [("docker", "Runs all Noomesh services"), ("git", "Version control")] {
        match tool_version(tool) {
            Some(v) => ctx.success(&format!("{tool}: {v}")),
            None => {
                ctx.error(&format!("{tool}: MISSING — {purpose}"));
                if tool == "docker" { docker_missing = true; } else { missing_apt.push(tool); }
                all_ok = false;
            }
        }
    }
    for (tool, purpose) in [
        ("nvidia-smi", "GPU detection"),
        ("curl", "HTTP health checks"),
        ("ffmpeg", "Audio/video processing"),
    ] {
        match tool_version(tool) {
            // A present optional tool is a pass — same ✓ as the required
            // ones instead of a bare info line (finding #69).
            Some(v) => ctx.success(&format!("{tool}: {v}")),
            None => {
                ctx.warn(&format!("{tool}: missing (optional — {purpose})"));
                if tool != "nvidia-smi" { missing_apt.push(tool); }
            }
        }
    }
    // The loader for noo's tab completion: install.sh drops the completion
    // FILE, but fresh Ubuntu server lacks the bash-completion package that
    // sources it — the file sits inert and "tab complete doesn't work"
    // (first contact). Not a tool_version probe: the package installs a
    // sourced script, not a binary.
    if !std::path::Path::new("/usr/share/bash-completion/bash_completion").exists() {
        ctx.warn("bash-completion: missing (optional — noo tab completion stays inactive)");
        missing_apt.push("bash-completion");
    }
    // `setfacl` (the `acl` package) is how this CLI hands a 0640 private
    // key to a container uid it is not a member of — loki, prometheus,
    // alertmanager, node-exporter, llamacpp, the gateway (65532), postgres
    // (70). Without it a key it cannot chgrp stays 0644, readable by every
    // local user, until a printed `sudo chgrp` runs.
    if tool_version("setfacl").is_none() {
        ctx.warn("setfacl: missing (the `acl` package — without it, keys read by a non-root container stay world-readable until a sudo line runs)");
        missing_apt.push("acl");
    }

    // ── Offer to install what's missing (fresh-box first contact, 2026-08-19).
    // The wizard already curl|sh-installs Tailscale, and the node paste's
    // prep-host installs docker — the controller's own prerequisites were the
    // one place a fresh box got a list of errors instead of an offer. Same
    // consent posture as the Tailscale step: interactive terminal, explicit
    // yes, sudo prompts visibly. apt-only (the fresh-box target); other
    // distros keep the manual hints above.
    if (docker_missing || !missing_apt.is_empty())
        && !ctx.non_interactive && !ctx.dry_run
        && ctx.ui.inherit_stdio() && super::prompt::stdin_is_tty()
        && Command::new("apt-get").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
    {
        let mut named: Vec<String> = missing_apt.iter().map(|s| s.to_string()).collect();
        if docker_missing { named.push("docker (get.docker.com — includes compose v2)".into()); }
        ctx.info(&format!("Missing: {}", named.join(", ")));
        if ctx.asker.confirm("Install the missing prerequisites now? (uses sudo)", true) {
            // curl first — docker's installer needs it.
            let mut apt_pkgs: Vec<&str> = missing_apt.clone();
            if docker_missing && !apt_pkgs.contains(&"curl") && tool_version("curl").is_none() {
                apt_pkgs.push("curl");
            }
            if !apt_pkgs.is_empty() {
                ctx.progress(&format!("Installing via apt: {} ...", apt_pkgs.join(" ")));
                let ok = ctx_sudo(ctx)
                    .args(["sh", "-c",
                        &format!("apt-get update -q && apt-get install -y -q {}", apt_pkgs.join(" "))])
                    .status().map(|s| s.success()).unwrap_or(false);
                if ok { ctx.success("apt packages installed"); }
                else { ctx.warn("apt install failed — install manually and re-run"); }
            }
            if docker_missing {
                // The official script over Ubuntu's docker.io package,
                // deliberately: docker.io ships WITHOUT the compose v2
                // plugin the stack needs.
                ctx.progress("Installing Docker (get.docker.com)...");
                // Downloaded to a file, checked, digest printed, then run —
                // never piped into a shell. See crate::vendor.
                let docker_cmd = crate::vendor::install_script_cmd(crate::vendor::DOCKER_INSTALL_URL);
                let ok = ctx_sudo(ctx)
                    .args(["sh", "-c", &docker_cmd])
                    .status().map(|s| s.success()).unwrap_or(false);
                if ok {
                    let user = std::env::var("USER").unwrap_or_default();
                    let _ = ctx_sudo(ctx).args(["usermod", "-aG", "docker", &user]).status();
                    ctx.success("Docker installed; your user was added to the docker group");
                    // The running shell can't pick up new group membership —
                    // but `sg docker` reads /etc/group directly (usermod just
                    // updated it), so the wizard RELAUNCHES ITSELF through it
                    // with the original argv: fully automatic, no re-login.
                    // First contact (host1 2026-08-19) also showed the
                    // old `return false` fell through to the generic
                    // "Continue despite failures?" prompt — a yes there ran
                    // the wizard straight into docker permission-denied. So
                    // the fallback is a hard exit with instructions, never a
                    // continuable failure.
                    ctx.progress("Relaunching the wizard with the docker group active...");
                    let exe = std::env::current_exe()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| "noo".into());
                    let argv: Vec<String> = std::env::args().skip(1).collect();
                    // sg first (classic), but Ubuntu 25.10 "resolute" ships
                    // WITHOUT sg (found live on host1) — `sudo -g
                    // docker` is the no-extra-package fallback: same user,
                    // docker as the effective group, args passed directly
                    // (no shell quoting), one more sudo prompt at most.
                    let quoted: Vec<String> = std::iter::once(&exe).chain(argv.iter())
                        .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
                        .collect();
                    let relaunch_may_prompt = ctx_sudo_may_prompt(ctx);
                    let code = Command::new("sg")
                        .args(["docker", "-c", &quoted.join(" ")])
                        .status().ok().and_then(|s| s.code())
                        .or_else(|| {
                            ctx.info("(sg not available — relaunching via `sudo -g docker`)");
                            sudo_cmd(relaunch_may_prompt)
                                .args(["-g", "docker", &exe])
                                .args(&argv)
                                .status().ok().and_then(|s| s.code())
                        });
                    match code {
                        Some(c) => std::process::exit(c),
                        None => {
                            ctx.warn("Automatic relaunch failed. Log out/in and re-run:");
                            ctx.warn("  noo onboard --standalone");
                            std::process::exit(64);
                        }
                    }
                }
                ctx.warn("Docker install failed — see https://docs.docker.com/engine/install/");
            }
            // Re-check the required pair after installs.
            all_ok = tool_version("docker").is_some() && tool_version("git").is_some();
        }
    }

    // Compose v2 is a prerequisite of its own: Ubuntu's `docker.io` ships
    // WITHOUT it (separate `docker-compose-v2` package), and step 7's launcher
    // runs `docker compose …` for everything. Failure semantics:
    //   ABSENT  (no `compose` subcommand / plugin)   -> FAIL, name the package
    //   OLD     (only the v1 `docker-compose` binary) -> same FAIL: `docker
    //           compose` is the v2 plugin, v1 is never consulted
    //   PRESENT -> print its version next to the docker row
    // Skipped when docker itself is missing: that row already failed.
    if tool_version("docker").is_some() {
        match probe_compose("docker") {
            Ok(v) => ctx.success(&format!("docker compose: {v}")),
            Err(why) => {
                ctx.error("docker compose: MISSING — the Compose v2 plugin runs every service");
                ctx.error(&format!("  `docker compose version` failed: {why}"));
                ctx.error(&format!("  {}", compose_remedy(&os_release_text(), docker_ce_installed())));
                all_ok = false;
            }
        }
    }

    ctx.progress("Checking Docker daemon...");
    if sh::docker_daemon_running() {
        ctx.success("Docker daemon: running");
    } else {
        ctx.error("Docker daemon: NOT RUNNING — start Docker first");
        all_ok = false;
    }

    ctx.progress("Checking Docker Hub login...");
    if sh::docker_logged_in() {
        ctx.success("Docker Hub: logged in");
    } else {
        // When the base images come from OUR ghcr mirrors (NOO_BASE_REGISTRY,
        // the standalone default), a Docker Hub account is genuinely OPTIONAL
        // — only anonymous-pull rate limits ride on it. First contact showed
        // the auto-attempted `docker login` was undeclinable: Ctrl+C at its
        // device-code prompt killed the whole wizard (same process group).
        // ASK, with a default that reflects whether Hub is actually needed.
        let mirrored = ctx.read_env("NOO_BASE_REGISTRY").trim().trim_end_matches('/') == crate::registry::PUBLIC_BASE_REGISTRY
            || std::env::var("NOO_BASE_REGISTRY").map(|v| !v.trim().is_empty()).unwrap_or(false);
        if mirrored {
            ctx.info("Docker Hub: not logged in — OPTIONAL (base images come from the ghcr mirrors;");
            ctx.info("a free account only raises anonymous pull rate limits)");
        } else {
            ctx.warn("Docker Hub: not logged in — needed for hardened base images (free account)");
        }
        // Interactive `docker login` needs the real terminal — skipped when a
        // full-screen frontend owns it (the TUI shows the manual hint above).
        if !ctx.non_interactive && !ctx.dry_run && ctx.ui.inherit_stdio() && super::prompt::stdin_is_tty() {
            if ctx.asker.confirm("Log in to Docker Hub now?", !mirrored) {
                let ok = Command::new("docker").arg("login").status().map(|s| s.success()).unwrap_or(false);
                if ok {
                    ctx.success("Docker Hub: logged in");
                } else {
                    ctx.warn("Docker Hub: skipped — run 'docker login' later");
                }
            } else {
                ctx.info("Skipped — run 'docker login' any time if pulls get rate-limited");
            }
        } else {
            ctx.info("Run: docker login");
        }
    }

    ctx.progress("Detecting GPU...");
    match util::detect_gpu() {
        Some((model, vram)) => {
            ctx.state.gpu_model = model.clone();
            ctx.state.vram_gb = vram;
            ctx.state.tier = util::tier_for_vram(vram);
            ctx.success(&format!("GPU: {model} ({vram:.0} GB) — Tier {}", ctx.state.tier));
        }
        None => {
            ctx.state.tier = 3;
            ctx.warn("GPU: none detected — CPU-only (Tier 3)");
        }
    }

    // ── NVIDIA container toolkit (first-contact finding #14) ────────────
    // The box can HAVE the driver (nvidia-smi works) while Docker still
    // can't hand GPUs to containers — get.docker.com does not install the
    // container toolkit, so every GPU backend silently runs CPU-only and a
    // GPU-less runtime check downstream reads as "no GPU". Same recipe as
    // the node-side prep-host.sh, offered with the same consent posture as
    // the other installers.
    let have_driver = Command::new("nvidia-smi").output().map(|o| o.status.success()).unwrap_or(false);
    let runtime_ready = Command::new("docker")
        .args(["info", "--format", "{{json .Runtimes}}"])
        .output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("nvidia"))
        .unwrap_or(false);
    if have_driver && !runtime_ready
        && !ctx.non_interactive && !ctx.dry_run && ctx.ui.inherit_stdio()
        && super::prompt::stdin_is_tty()
        && Command::new("apt-get").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
    {
        ctx.warn("NVIDIA driver present but Docker lacks the nvidia runtime —");
        ctx.warn("GPU model serving would silently run CPU-only.");
        if ctx.asker.confirm("Install the NVIDIA Container Toolkit now? (uses sudo)", true) {
            ctx.progress("Installing NVIDIA Container Toolkit...");
            // Mirrors prep-host.sh's node recipe (keep the two in sync).
            let script = r#"set -e
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey |   gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -sL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list |   sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g'   > /etc/apt/sources.list.d/nvidia-container-toolkit.list
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nvidia-container-toolkit
nvidia-ctk runtime configure --runtime=docker
systemctl restart docker"#;
            let ok = ctx_sudo(ctx).args(["sh", "-c", script])
                .status().map(|st| st.success()).unwrap_or(false);
            if ok {
                ctx.success("NVIDIA Container Toolkit installed; Docker restarted with the nvidia runtime");
            } else {
                ctx.warn("Toolkit install failed — GPU backends will run CPU-only;");
                ctx.warn("see https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/");
            }
        } else {
            ctx.info("Skipped — GPU backends run CPU-only until the toolkit is installed.");
        }
    }

    // Security readiness (informational)
    let ca = ctx.pki_dir.join("ca.crt").exists() && ctx.pki_dir.join("ca.key").exists();
    ctx.info(if ca { "PKI certs: CA present" } else { "PKI certs: not yet (Step 3)" });
    let n_secrets = SECRETS
        .iter()
        .filter(|(_, env_var)| ctx.secret_present(env_var))
        .count();
    ctx.info(&format!("Secrets: {n_secrets} present"));

    // Backends for this tier
    ctx.info("Available LLM backends for your hardware:");
    match ctx.state.tier {
        1 => {
            ctx.info("  vLLM — fastest inference, AWQ/GPTQ quantized (recommended)");
            ctx.info("  Ollama — simple setup, GGUF quantized");
            ctx.info("  llama.cpp — flexible, GGUF with GPU offload");
        }
        2 => {
            ctx.info("  Ollama — best for 4-10 GB VRAM (recommended)");
            ctx.info("  llama.cpp — GGUF with partial GPU offload");
        }
        _ => ctx.info("  Ollama — CPU inference, GGUF quantized (recommended)"),
    }

    // NOTE: Python's Step 1 also runs `pip install -e .` to sync the host
    // package. That is only for the Python CLI/venv — the cluster runs from
    // Docker images — so the zero-Python bootstrap deliberately skips it.
    ctx.info("Python dep sync skipped (not needed — cluster runs from Docker images)");

    if all_ok {
        ensure_shell_completion(ctx);
    ctx.success("All prerequisites met");
    } else {
        ctx.warn("Some prerequisites are missing");
    }
    all_ok
}

/// Run `<docker> compose version` and return the version text, or the last
/// non-empty line of what it said when it fails (spawn error included). Takes
/// the docker binary as an argument so a test can hand it a fake.
pub(crate) fn probe_compose(docker: &str) -> Result<String, String> {
    match Command::new(docker).args(["compose", "version"]).output() {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            let line = text.lines().next().unwrap_or("").trim();
            // "Docker Compose version v2.40.3" -> "v2.40.3"
            Ok(line.rsplit(' ').next().filter(|v| !v.is_empty()).unwrap_or("present").to_string())
        }
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stderr);
            let last = text.lines().rev().map(str::trim).find(|l| !l.is_empty());
            Err(last.map(str::to_string).unwrap_or_else(|| format!("exit {}", o.status.code().unwrap_or(-1))))
        }
        Err(e) => Err(format!("could not run {docker}: {e}")),
    }
}

/// The package that supplies the compose v2 plugin, from `/etc/os-release`
/// text (passed in, never read here). `docker_ce` says Docker's own apt
/// repository supplied docker (`docker-compose-plugin`) rather than the
/// distro's `docker.io` (`docker-compose-v2`). None = not a Debian family
/// distro, so no package name is claimed.
pub(crate) fn compose_package(os_release: &str, docker_ce: bool) -> Option<&'static str> {
    let field = |key: &str| -> String {
        os_release.lines()
            .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
            .map(|v| v.trim().trim_matches('"').to_lowercase())
            .unwrap_or_default()
    };
    let (id, like) = (field("ID"), field("ID_LIKE"));
    let debian = |w: &str| w == "ubuntu" || w == "debian";
    if debian(&id) || like.split_whitespace().any(debian) {
        Some(if docker_ce { "docker-compose-plugin" } else { "docker-compose-v2" })
    } else {
        None
    }
}

fn compose_remedy(os_release: &str, docker_ce: bool) -> String {
    match compose_package(os_release, docker_ce) {
        Some(pkg) => format!("install it with: sudo apt install {pkg}  (Compose v2, not the old docker-compose)"),
        None => "install the Docker Compose v2 plugin (not the old docker-compose): https://docs.docker.com/compose/install/linux/".into(),
    }
}

fn os_release_text() -> String {
    std::fs::read_to_string("/etc/os-release").unwrap_or_default()
}

/// True when docker came from Docker's apt repository (`docker-ce`).
fn docker_ce_installed() -> bool {
    Command::new("dpkg-query").args(["-W", "docker-ce"]).output().map(|o| o.status.success()).unwrap_or(false)
}

fn tool_version(tool: &str) -> Option<String> {
    let out = Command::new(tool).arg("--version").output().ok()?;
    if !out.status.success() && out.stdout.is_empty() && out.stderr.is_empty() {
        return None;
    }
    // presence is what matters; report the first line truncated
    let text = if !out.stdout.is_empty() {
        String::from_utf8_lossy(&out.stdout).into_owned()
    } else {
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    let first = text.lines().next().unwrap_or("").trim().to_string();
    // "curl 8.18.0 (x86_64-pc-linux-gnu) libcurl/… OpenSSL/… brotli" tells
    // the operator nothing past the version — cut at the parenthetical and
    // cap the tail (readability, finding #69).
    let first = first.split(" (").next().unwrap_or(&first).to_string();
    Some(if first.len() > 48 { first[..48].to_string() } else { first })
}

// ── Step 2: Environment ──────────────────────────────────────────────────

/// The standalone embedder's mTLS door: the stunnel-ollama-embed sidecar by
/// its container name (the `ollama-embed` leaf's SANs carry it). Pinned by
/// `tests/test_ollama_embed_mtls.py` against the launchers' default.
pub(crate) const STANDALONE_OLLAMA_EMBED_URL: &str = "https://noo-stunnel-ollama-embed:11434";

/// The service-topology env for THIS install shape — standalone (one box,
/// one ollama for chat + embeddings behind its stunnel sidecar, no
/// loki/vllm) vs the multi-node controller. One function, called from the env step (so
/// `noo onboard --only env` converges it — 2026-09-02: it lived only in
/// the PKI step, and a 0.3.31 install had no OLLAMA_URL at all) and from
/// the PKI step, where it was born. Idempotent.
fn apply_topology_env(ctx: &mut Ctx) {
    let standalone = ctx.repo_root.join(".noo-standalone").exists();
    if standalone {
        // The coherent embed quad for the standalone profile: the always-on
        // ollama-embed container, ollama wire format, and harrier — the
        // product's default 1024-dim embedder (trellion's DDL hardcodes
        // vector(1024); preflight refuses mismatched embed writes; the old
        // 768 default here and in config.py never matched the DDL). The
        // services step fetches/creates the model (models-harrier-v1
        // release — harrier is locally converted, not registry-pullable).
        // Every one of these dials the ollama-embed container through its
        // stunnel-ollama-embed sidecar (mTLS, client certificate required;
        // docker/stunnel-ollama-embed.conf): the gateway presents its own
        // leaf (tls::cluster_client()), the worker the same leaf via
        // NOO_TLS_CERT. `http://ollama-embed:11434` is the plaintext door
        // that stays reachable on the compose network beside the sidecar
        //  — never written here again; the launchers
        // rewrite that literal in an old .env until this step converges it.
        for (k, v) in [
            ("PAGEINDEX_EMBEDDING_URL", STANDALONE_OLLAMA_EMBED_URL),
            ("PAGEINDEX_EMBEDDING_BACKEND", "ollama"),
            ("PAGEINDEX_EMBEDDING_MODEL", "harrier"),
            ("EMBEDDING_DIM", "1024"),
            // Blank the tiered-topology pointers a previous run (or a
            // migrated .env) may have left — empty falls through to the
            // code/compose resolution instead of a dead literal.
            // Chat's static last resort (gateway backend.rs): the same single
            // ollama that serves embeddings. Blank here (2026-09-01 quad) left
            // the gateway on the compose default `stunnel-ollama`, which does
            // not exist on standalone — every chat channel failed.
            ("OLLAMA_URL", STANDALONE_OLLAMA_EMBED_URL),
            // No PAGEINDEX_LLM_URL (i145): the worker's LLM calls go through
            // the gateway as a purpose; the env value is ignored.
            ("LOKI_URL", ""),
            ("LOKI_PUSH_URL", ""),
        ] {
            ctx.update_env(k, v);
        }
    } else {
        // Tiered/controller install: loki rides the controller profile;
        // the ollama pointer follows the GPU tier that deploys it.
        ctx.update_env("LOKI_URL", "https://loki:3100");
        ctx.update_env("LOKI_PUSH_URL", "https://loki:3100/loki/api/v1/push");
        if ctx.state.tier == 2 {
            ctx.update_env("OLLAMA_URL", "https://stunnel-ollama:11434");
        }
        // No PAGEINDEX_EMBEDDING_URL: tei is opt-in (tei-compose) and the
        // embedding client resolves ollama-first / mesh-routed without it.
    }
}

/// Offer to delete the retired keys the launcher warns about on every start
/// (`scripts/retired-env-keys`, the one list). Lists them, confirms (default
/// no — and `--ci` never removes), backs `.env` up as `.env.bak_<ts>` first.
/// Returns whether `.env` changed.
fn offer_retired_env_keys(ctx: &mut Ctx) -> bool {
    let set = env::retired_keys_set(&ctx.env_path, &env::retired_env_keys());
    if set.is_empty() {
        return false;
    }
    ctx.warn(&format!("{} retired key(s) in .env — nothing reads them any more:", set.len()));
    for (k, note) in &set {
        ctx.raw(&format!("      {k} — {note}"));
    }
    // i145: a model trellion was pointed at is a preference worth keeping.
    // Say the exact command before the line goes, so the choice is carried
    // into the DB instead of lost with the env value.
    let (existing, _) = env::env_map(&ctx.env_path);
    if let Some(cmd) = existing.get("PAGEINDEX_LLM_MODEL").and_then(|v| keep_llm_preference_hint(v)) {
        ctx.info(&format!("To keep trellion preferring that model: {cmd}"));
    }
    if ctx.dry_run {
        ctx.dry("offer to remove the retired .env keys (backup .env.bak_<ts> first)");
        return false;
    }
    if !ctx.asker.confirm("Remove them from .env now? (a backup is written first)", false) {
        ctx.info("Left in place. Remove later with: noo onboard --only env");
        return false;
    }
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let keys: Vec<String> = set.iter().map(|(k, _)| k.clone()).collect();
    match env::remove_retired_keys(&ctx.env_path, &keys, &ts.to_string()) {
        Ok(bak) => {
            ctx.success(&format!("removed {} from .env (backup: {})", keys.join(", "), bak.display()));
            true
        }
        Err(e) => {
            ctx.warn(&format!("could not remove the retired keys: {e}"));
            false
        }
    }
}

/// The `noo cluster prefer` command that carries a retired
/// `PAGEINDEX_LLM_MODEL` value into the DB, or None when it named no model
/// (blank, `default`, the purpose itself).
pub(crate) fn keep_llm_preference_hint(value: &str) -> Option<String> {
    let v = value.trim().trim_matches('"').trim_matches('\'');
    if v.is_empty() || ["default", "auto", "knowledge"].iter().any(|d| d.eq_ignore_ascii_case(v)) {
        return None;
    }
    Some(format!("noo cluster prefer knowledge {v}"))
}

pub fn environment(ctx: &mut Ctx) {
    // Before the read: a removal must not be written straight back by the merge below.
    offer_retired_env_keys(ctx);
    let (existing, order) = env::env_map(&ctx.env_path);
    let get = |k: &str| existing.get(k).cloned().unwrap_or_default();
    if !existing.is_empty() {
        // A standalone first run arrives here with the 4 keys prepare()
        // seeded (install mode, profile, image tag+prefix) — "existing"
        // read as suspicious leftovers on first contact. Name the source.
        if std::env::var("NOO_STANDALONE").as_deref() == Ok("1")
            && existing.len() <= 6
            && existing.contains_key("NOO_INSTALL_MODE")
        {
            ctx.info(&format!(
                "Using the {} settings seeded by --standalone (install mode, image pin)",
                existing.len()));
        } else {
            ctx.info(&format!("Found existing .env with {} keys", existing.len()));
        }
    }

    let hostname = Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "mesh-node".to_string());

    let (mode, node_id, node_ip, controller_url);
    if ctx.non_interactive {
        node_id = if get("NODE_ID").is_empty() { hostname.clone() } else { get("NODE_ID") };
        node_ip = if get("NODE_IP").is_empty() { detect_ip_env() } else { get("NODE_IP") };
        mode = "controller".to_string();
        controller_url = String::new();
    } else {
        ctx.info("Controller = runs the gateway/db and coordinates the cluster.");
        ctx.info("Worker = GPU node that receives inference jobs from a controller.");
        let m = ctx.asker.ask(&Prompt::new("Node mode (controller / worker)").default("controller"));
        mode = if m == "worker" { "worker".to_string() } else { "controller".to_string() };
        node_id = ctx.asker.ask(
            &Prompt::new("Node ID (unique name for this node)")
                .default(if get("NODE_ID").is_empty() { hostname.clone() } else { get("NODE_ID") }),
        );
        node_ip = ctx.asker.ask(
            &Prompt::new("Node IP (auto-corrected to the tailnet address after Step 3's join)")
                .default(if get("NODE_IP").is_empty() { detect_ip_env() } else { get("NODE_IP") }),
        );
        controller_url = if mode == "worker" {
            ctx.asker.ask(
                &Prompt::new("Controller URL (HTTPS if TLS enabled)")
                    .default(if get("CONTROLLER_URL").is_empty() {
                        "https://10.0.0.1:8080".to_string()
                    } else {
                        get("CONTROLLER_URL")
                    }),
            )
        } else {
            String::new()
        };
    }
    ctx.state.mode = mode.clone();
    ctx.state.controller_url = controller_url.clone();

    // Instance namespace. One checkout =
    // one instance; the name prefixes containers/network/volumes and the
    // offset shifts every host port, so mesh-galaxy and mesh-world run
    // side by side. Default stays `mesh` (no prefix, stock ports) —
    // byte-identical for everyone who just presses enter.
    let mut instance = get("NOO_INSTANCE");
    let mut port_offset = get("NOO_PORT_OFFSET");
    if mode == "controller" && !ctx.non_interactive {
        // Our OWN running gateway also holds :8080 — a reconfigure of a
        // healthy install must not read as "another instance" and push the
        // operator toward a port offset that would rewrite a working stack
        // (live 2026-08-25, first-contact finding #34: default offset 1000
        // was one enter-press away). If the listener is this instance's own
        // gateway container, the port is OURS, not busy.
        let own_gateway_holds_8080 = {
            let name = crate::envfile::container("gateway");
            std::process::Command::new("docker")
                .args(["ps", "--filter", &format!("name={name}"),
                       "--filter", "publish=8080", "-q"])
                .output()
                .map(|o| o.status.success() && !o.stdout.is_empty())
                .unwrap_or(false)
        };
        let default_ports_busy = std::net::TcpListener::bind("127.0.0.1:8080").is_err()
            && !own_gateway_holds_8080
            && get("NOO_INSTANCE").is_empty();
        if own_gateway_holds_8080 {
            ctx.info("Port 8080 is held by this install's own gateway — not a collision.");
        }
        if default_ports_busy {
            ctx.warn("Port 8080 is already in use on this machine — another Noomesh instance?");
            ctx.raw("    A named instance with a port offset lets both run side by side");
            ctx.raw("    (e.g. name `galaxy`, offset 1000 \u{2192} gateway on :9080).");
        }
        instance = ctx.asker.ask(
            &Prompt::new("Instance name — SAME-MACHINE namespace for running a second \
stack beside this one (containers/ports/network). One install per machine? \
The default is right (press enter)")
                .default(if instance.is_empty() { "noomesh".to_string() } else { instance.clone() }),
        );
        // Both sentinels mean "the default instance": `noomesh` (current
        // label) and `mesh` (pre-rename; typed from muscle memory).
        if matches!(instance.trim(), "noomesh" | "mesh") {
            instance = String::new();
        }
        if !instance.is_empty() || default_ports_busy {
            port_offset = ctx.asker.ask(
                &Prompt::new("Port offset (added to every host port; 0 = stock ports)")
                    .default(if !port_offset.is_empty() {
                        port_offset.clone()
                    } else if default_ports_busy {
                        "1000".to_string()
                    } else {
                        "0".to_string()
                    }),
            );
        }
        if !instance.is_empty() {
            let off: u32 = port_offset.trim().parse().unwrap_or(0);
            ctx.success(&format!(
                "Instance `{instance}`: containers noo-{instance}-*, gateway on :{}",
                8080 + off
            ));
        }
    }

    // Optional API keys (interactive only)
    let (mut hf, mut anthropic, mut openai, mut tavily) = (String::new(), String::new(), String::new(), String::new());
    if !ctx.non_interactive {
        ctx.info("API keys are optional — local models work without any keys.");
        hf = ctx.asker.ask(&Prompt::new("HuggingFace token (blank to skip)").default(get("HF_TOKEN")).secret());
        anthropic = ctx
            .asker
            .ask(&Prompt::new("Anthropic API key (blank to skip)").default(get("ANTHROPIC_API_KEY")).secret());
        openai = ctx
            .asker
            .ask(&Prompt::new("OpenAI API key (blank to skip)").default(get("OPENAI_API_KEY")).secret());
        // Web search. Blank keeps DuckDuckGo, which needs no
        // key and which DuckDuckGo rate-limits at its own discretion — the
        // operator discovered that knob when a report failed (2026-09-27).
        // A Tavily key is one paste and a free tier.
        ctx.info("Web search: blank = DuckDuckGo (no key; may be rate-limited). A Tavily key (free at app.tavily.com) makes research runs reliable.");
        tavily = ctx
            .asker
            .ask(&Prompt::new("Tavily API key (blank to skip)").default(get("TAVILY_API_KEY")).secret());
    }

    // Build merged map (existing preserved, new values win) — parity with the
    // Python writer's `merged = dict(existing); merged.update(new_vals)`.
    let mut merged = existing.clone();
    let mut merged_order = order.clone();
    let set = |m: &mut std::collections::BTreeMap<String, String>,
                   ord: &mut Vec<String>,
                   k: &str,
                   v: String| {
        if !m.contains_key(k) {
            ord.push(k.to_string());
        }
        m.insert(k.to_string(), v);
    };
    set(&mut merged, &mut merged_order, "NODE_ID", node_id.clone());
    set(&mut merged, &mut merged_order, "NODE_IP", node_ip.clone());
    set(&mut merged, &mut merged_order, "CLUSTER_MODE", mode.clone());
    set(&mut merged, &mut merged_order, "NODE_TIER", ctx.state.tier.to_string());
    if !ctx.state.gpu_model.is_empty() {
        set(&mut merged, &mut merged_order, "GPU_MODEL", ctx.state.gpu_model.clone());
        set(&mut merged, &mut merged_order, "VRAM_GB", (ctx.state.vram_gb as i64).to_string());
    }
    if mode == "worker" && !controller_url.is_empty() {
        set(&mut merged, &mut merged_order, "CONTROLLER_URL", controller_url.clone());
    }
    // Provider keys are SECRETS: they never enter the .env body written
    // below. On an install already on the encrypted store they go straight
    // into it (after the write, so the whole-file write cannot race it);
    // before the store exists — this step runs one step ahead of it on a
    // fresh install — they wait in wizard memory for the secrets step, which
    // arms the store and then saves them. They used to be written here in
    // plaintext and encrypted a step later, if the encryption worked.
    let provider_keys: Vec<(String, String)> = [
        ("ANTHROPIC_API_KEY", &anthropic),
        ("OPENAI_API_KEY", &openai),
        ("HF_TOKEN", &hf),
        ("TAVILY_API_KEY", &tavily),
    ]
    .into_iter()
    .filter(|(k, v)| !v.is_empty() && *v != &get(k))
    .map(|(k, v)| (k.to_string(), v.clone()))
    .collect();
    // A key without the provider set is a key nothing reads: name the
    // provider in the same breath. A provider the operator already chose
    // (searxng, brave) is left alone.
    if !tavily.is_empty() && get("NOO_SEARCH_PROVIDER").is_empty() {
        set(&mut merged, &mut merged_order, "NOO_SEARCH_PROVIDER", "tavily".to_string());
    }
    // Bootstrap pair: written only when meaningful — an absent
    // NOO_INSTANCE IS the default instance, and writing `mesh` would
    // just invite edits.
    if !instance.trim().is_empty() {
        set(&mut merged, &mut merged_order, "NOO_INSTANCE", instance.trim().to_string());
    }
    let off_trim = port_offset.trim();
    if !off_trim.is_empty() && off_trim != "0" {
        set(&mut merged, &mut merged_order, "NOO_PORT_OFFSET", off_trim.to_string());
    }
    // Carry the pair in wizard state for the tailscale step (serve path +
    // gateway port) — envfile::instance() OnceLock-caches the pre-wizard
    // .env, so it cannot see what we are about to write.
    ctx.state.instance = if instance.trim() == "mesh" { String::new() } else { instance.trim().to_string() };
    ctx.state.port_offset = off_trim.parse().unwrap_or(0);

    ctx.progress("Writing environment configuration...");
    let now = util::local_timestamp();
    let body = env::render_sectioned(&merged, &merged_order, &now);
    if ctx.dry_run {
        ctx.dry(&format!("write sectioned .env ({} keys)", merged.iter().filter(|(_, v)| !v.is_empty()).count()));
        ctx.state.env_written = true;
        // The two writes that ride on the back of the .env write. Returning
        // here left them out of the plan entirely — an operator reading a
        // dry run saw no mention of the topology keys or the noomesh.yaml
        // seed, which are precisely the ones they would want to check.
        apply_topology_env(ctx);
        ensure_mesh_yaml(ctx);
        return;
    }
    if let Err(e) = std::fs::write(&ctx.env_path, body) {
        ctx.error(&format!("Failed to write .env: {e}"));
        return;
    }
    ctx.state.env_written = true;
    if ctx.sops_active() {
        for (k, v) in &provider_keys {
            ctx.update_env(k, v);
        }
    } else {
        ctx.state.pending_secrets.extend(provider_keys);
    }
    apply_topology_env(ctx);
    ctx.success(&format!("Environment written to {}", ctx.env_path.display()));
    ctx.warn_sops_once();

    ensure_mesh_yaml(ctx);
}

/// noomesh.yaml is gitignored operator config but three services
/// BIND-MOUNT it — when the file is absent at `up`, docker creates a
/// DIRECTORY at the path and the gateway crash-loops on "Is a directory"
/// (defect #15, sandbox rehearsal). Seed it from the example on fresh
/// installs, and repair the docker-created directory when found.
fn ensure_mesh_yaml(ctx: &mut Ctx) {
    let yaml = ctx.repo_root.join("noomesh.yaml");
    let example = ctx.repo_root.join("noomesh.yaml.example");
    if yaml.is_dir() {
        if ctx.dry_run {
            ctx.dry("remove docker-created noomesh.yaml DIRECTORY, seed from example");
            return;
        }
        // Only ever a docker artifact — a real config is a file.
        let _ = std::fs::remove_dir_all(&yaml);
        ctx.warn("noomesh.yaml was a DIRECTORY (docker bind-mount artifact) — removed");
    }
    if yaml.exists() {
        return;
    }
    if ctx.dry_run {
        ctx.dry("seed noomesh.yaml from noomesh.yaml.example");
        return;
    }
    match std::fs::copy(&example, &yaml) {
        Ok(_) => ctx.success("noomesh.yaml seeded from example (edit later for runtime config)"),
        Err(e) => ctx.warn(&format!("could not seed noomesh.yaml: {e}")),
    }
}

fn detect_ip_env() -> String {
    let env_ip = std::env::var("NOO_CONTROLLER_IP").unwrap_or_default();
    if !env_ip.trim().is_empty() {
        return env_ip.trim().to_string();
    }
    util::detect_ip()
}


/// Shell completion, installed where bash-completion auto-loads user files.
/// install.sh drops it once, but a binary installed by hand (gh release
/// download — the host8 path, 2026-09-01) never gets one, and `noo
/// upgrade` only refreshes an EXISTING file (finding #55). The wizard is
/// the one gate every install passes through. Best-effort; bash only
/// (zsh/fish users get the hint).
fn ensure_shell_completion(ctx: &mut Ctx) {
    if ctx.dry_run {
        return;
    }
    // One installer for every install path (shell_completion.rs) — enroll
    // and upgrade call the same function, so a worker box completes too.
    match crate::shell_completion::ensure_installed(false) {
        Some(_) => ctx.success("Shell completion installed (bash — new shells tab-complete noo)"),
        None => {
            let present = std::env::var("HOME").ok()
                .map(|h| std::path::Path::new(&h).join(".local/share/bash-completion/completions/noo").exists())
                .unwrap_or(false);
            if !present {
                ctx.info("(shell completion not installed — `noo completions bash` prints it)");
            }
        }
    }
}

// ── Step 3: Security ─────────────────────────────────────────────────────

// ── Step 3: Tailscale Access ─────────────────────────────────────────────
// The access model is tailnet MagicDNS first:
// the dashboard is reached through `tailscale serve`, which terminates a
// public ts.net cert for the browser and proxies to the gateway's HTTPS,
// verifying the gateway cert against the LINUX system trust store. That
// only works when (a) the gateway cert carries the MagicDNS name + tailnet
// IP as SANs and (b) the cluster CA sits in the Linux store. This step owns
// (a)'s identity detection and the serve mapping; the security step
// consumes the identity at cert issuance and installs (b).
//
// The predecessor of this step was an OPPORTUNISTIC read buried in cert
// issuance that returned empty SANs on any failure and reported success
// anyway — the 2026-08-06 install shipped a cert the tailnet could not
// verify (502 from tailscale serve). Absence is now loud, never silent.

/// Self-identity as reported by `tailscale status --json`.
pub(crate) fn tailscale_identity() -> Result<(String, String), String> {
    let out = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .map_err(|e| format!("could not run tailscale: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("tailscale status failed: {}", err.trim()));
    }
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("unparseable tailscale status: {e}"))?;
    // Self.DNSName survives in the state file after the account behind it is
    // gone (deleted tailnet, `logout` that 500'd with "no nodekey"): a Stopped
    // daemon still reports the dead identity, and trusting it sent step 4 down
    // the joined path with an unreachable address (first-contact finding #17).
    let state = json["BackendState"].as_str().unwrap_or("");
    if state != "Running" {
        return Err(format!(
            "tailscaled is not connected (state: {}) — ignoring any cached identity",
            if state.is_empty() { "unknown" } else { state }
        ));
    }
    let self_ = &json["Self"];
    let dns = self_["DNSName"].as_str().unwrap_or("").trim_end_matches('.').to_string();
    let ip = self_["TailscaleIPs"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .find(|s| !s.contains(':')) // v4 only
        })
        .unwrap_or("")
        .to_string();
    if dns.is_empty() || ip.is_empty() {
        return Err("tailscaled is running but not joined to a tailnet (no MagicDNS name/IP)".into());
    }
    Ok((dns, ip))
}

/// Returns false when the user chose to abort setup rather than continue
/// without a tailnet (mirrors `prerequisites`' abort contract).
/// Is the tailscale binary present?
/// The controller MUST advertise tag:controller or the ACL's
/// `tag:worker → tag:controller:<ports>` rules match nothing and every
/// node's traffic silently times out (host8 live-fire, 2026-09-01: the
/// controller had joined as tag:worker and enrollment died in mystery
/// timeouts; this step used to check only that the tag NAMES exist in the
/// ACL). Self-service tagging is deliberately impossible in tailscale
/// (privilege escalation), so: assert via the tailnet API when the
/// operator granted a key (NOO_TS_API_KEY, device-write scope), else the
/// HTTPS-cert-style guided wait loop, else a loud warning.
fn ensure_controller_tag(ctx: &mut Ctx) {
    if ctx.dry_run {
        return;
    }
    // A single box has no node traffic for the tag to govern. Without it
    // this warned "every node's traffic will silently time out" on a box
    // with no tailnet at all, then offered five 15-second re-checks that
    // could not succeed (tag:controller is declared only in the multinode
    // branch). Say what is true and move on.
    if ctx.state.ts_ip.is_empty() {
        ctx.info("No tailnet on this box — the controller tag applies once you add nodes: tailscale up, then noo onboard --only enrollment");
        return;
    }
    if ctx.state.multinode == Some(false) {
        ctx.info("Single box for now — when you add nodes, `noo cluster invite` walks you through tagging this machine tag:controller first");
        return;
    }
    let self_tags = || -> String {
        Command::new("tailscale")
            .args(["status", "--self=true", "--peers=false", "--json"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };
    let out = self_tags();
    if out.contains("tag:controller") {
        ctx.success("Tailnet tag verified: this machine advertises tag:controller");
        return;
    }
    ctx.warn("This machine does NOT advertise tag:controller — the ACL's worker→controller");
    ctx.raw("    rules will match nothing and every node's traffic will silently time out.");
    // The credential the multinode capture already stores: a plain
    // API key (NOO_TAILSCALE_API_KEY, basic auth) or an OAuth client
    // (exchanged for a short-lived token, never stored). Doctrine home is
    // the sops store; process env is the override lane.
    let store = crate::commands::secrets::SecretStore::load_sops(
        &ctx.repo_root.join("secrets/env.sops"),
    )
    .ok();
    let api_auth: Option<(String, String)> = {
        let env_key = std::env::var("NOO_TAILSCALE_API_KEY").unwrap_or_default();
        let plain = if !env_key.trim().is_empty() {
            Some(env_key)
        } else {
            store
                .as_ref()
                .and_then(|st| st.value_for_provider_api("NOO_TAILSCALE_API_KEY"))
        };
        match plain {
            Some(k) if !k.trim().is_empty() => Some(("-u".into(), format!("{}:", k.trim()))),
            _ => store
                .as_ref()
                .and_then(|st| {
                    Some((
                        st.value_for_provider_api("NOO_TAILSCALE_OAUTH_CLIENT_ID")?,
                        st.value_for_provider_api("NOO_TAILSCALE_OAUTH_CLIENT_SECRET")?,
                    ))
                })
                .and_then(|(id, sec)| {
                    crate::commands::cluster_provision::mint_oauth_token(id.trim(), sec.trim())
                })
                .map(|tok| ("-H".into(), format!("Authorization: Bearer {tok}"))),
        }
    };
    if let Some((auth_flag, auth_val)) = &api_auth {
        // Node id ("n…") from the same status JSON; the v2 device API takes it.
        let node_id = out
            .split("\"ID\":")
            .nth(1)
            .and_then(|s| s.split('"').nth(1))
            .unwrap_or("")
            .to_string();
        if !node_id.is_empty() {
            // The tag NAME comes from the constant, not a literal here. This
            // is the only remaining spelling in this file and the anti-drift
            // guard in commands::tailnet_policy pins that it stays that way:
            // the wizard's job is to render the declaration, never restate it.
            let controller_tag = crate::commands::kiosk::CONTROLLER_TAG;
            ctx.progress(&format!("Asserting {controller_tag} via the tailnet API..."));
            let tag_body = format!("{{\"tags\":[\"{controller_tag}\"]}}");
            // Keep the API's answer: `-fsS` + discarded output made every
            // failure read as "did not take" (host8 2026-09-01). The body
            // names the real cause (scope, tagOwners, unknown device).
            let out = Command::new("curl")
                .args([
                    "-sS", "-X", "POST",
                    "-w", "\n%{http_code}",
                    &format!("https://api.tailscale.com/api/v2/device/{node_id}/tags"),
                    auth_flag, auth_val,
                    "-H", "Content-Type: application/json",
                    "-d", &tag_body,
                ])
                .output();
            let (code, body) = out
                .map(|o| {
                    let text = String::from_utf8_lossy(&o.stdout).to_string();
                    let (body, code) = text.rsplit_once('\n').unwrap_or(("", text.as_str()));
                    (code.trim().to_string(), body.trim().to_string())
                })
                .unwrap_or_default();
            if code.starts_with('2') {
                // The API accepted it; the node learns its tags on the next
                // netmap push — poll instead of judging instantly.
                for _ in 0..10 {
                    if self_tags().contains("tag:controller") {
                        ctx.success("tag:controller asserted via the tailnet API");
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(3));
                }
                ctx.warn("API accepted the tag but this node has not picked it up yet (netmap propagation) — falling back to the console check.");
            } else {
                let why: String = if body.is_empty() { "no response".to_string() } else { body.chars().take(200).collect() };
                let code = if code.is_empty() { "?".to_string() } else { code };
                ctx.warn(&format!("API tag assertion failed (HTTP {code}): {why}"));
                ctx.info("Usually: the OAuth client lacks “Devices → Core: write”, or tagOwners for tag:controller does not include this client — falling back to the console.");
            }
        }
    }
    ctx.raw(&format!(
        "    Fix (30s): {TS_DNS_CONSOLE_MACHINES} → this machine → Edit ACL tags → tag:controller"
    ));
    if !ctx.non_interactive {
        for _ in 0..5 {
            if !ctx.asker.confirm("Tagged it in the console? Re-check now?", true) {
                break;
            }
            let mut seen = false;
            for _ in 0..5 {
                std::thread::sleep(std::time::Duration::from_secs(3));
                if self_tags().contains("tag:controller") {
                    seen = true;
                    break;
                }
            }
            if seen {
                ctx.success("Tailnet tag verified: tag:controller");
                return;
            }
            ctx.warn("Still not advertising tag:controller after 15s. If the console shows the tag, re-claim it locally:");
            ctx.raw("      sudo tailscale up --advertise-tags=tag:controller  (repeat your --operator/--hostname flags)");
        }
    }
    ctx.warn("Continuing WITHOUT a verified controller tag — node enrollment will time out until it is set.");
}

const TS_DNS_CONSOLE_MACHINES: &str = "https://login.tailscale.com/admin/machines";

fn tailscale_installed() -> bool {
    Command::new("tailscale")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Tailnet-level facts the joined daemon exposes locally — no API key
/// needed. `cert_domains_enabled` is the reliable HTTPS-certificates
/// signal: `tailscale serve` fails without it, and the old diagnosis
/// ("needs root or --operator") was WRONG for that case.
struct TailnetFacts {
    magic_dns_enabled: bool,
    cert_domains_enabled: bool,
    health: Vec<String>,
}

fn tailnet_facts() -> TailnetFacts {
    let json: serde_json::Value = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice(&o.stdout).ok())
        .unwrap_or_default();
    TailnetFacts {
        magic_dns_enabled: json["CurrentTailnet"]["MagicDNSEnabled"]
            .as_bool()
            .unwrap_or(false),
        cert_domains_enabled: json["CertDomains"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        health: json["Health"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
    }
}

/// The tailnet admin-console pages the detection below points at.
const TS_DNS_CONSOLE: &str = "https://login.tailscale.com/admin/dns";
const TS_OAUTH_CONSOLE: &str = "https://login.tailscale.com/admin/settings/oauth";
// The /file suffix matters: it lands ON the JSON policy editor, while the
// bare /admin/acls page made users hunt for it. Operator-verified URL from
// the live console, 2026-08-20 (first-contact finding #18).
const TS_ACL_CONSOLE: &str = "https://console.tailscale.com/admin/acls/file";

/// The pending login URL, present while tailscaled waits for browser auth.
fn tailscale_auth_url() -> Option<String> {
    let json: serde_json::Value = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice(&o.stdout).ok())?;
    json["AuthURL"]
        .as_str()
        .filter(|u| !u.is_empty())
        .map(str::to_string)
}

/// Assisted join for frontends WITHOUT a terminal to hand over
/// item 3, the web wizard). Two shapes:
///
/// - tailscaled reachable by this process (root, or operator already
///   set): spawn `tailscale login` in the background and surface its
///   AuthURL in the wizard UI — the user opens it on ANY device, and it
///   doubles as account signup.
/// - no rights on the socket: show the exact command to run in a
///   terminal and AUTO-DETECT the join by polling, so the user never has
///   to tell the wizard "done".
fn assisted_join(ctx: &Ctx, up_cmd: &str) -> Result<(String, String), String> {
    let mut child = Command::new("tailscale")
        .arg("login")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok();
    if child.is_none() {
        ctx.warn(&format!(
            "Can't drive the join from here — run `{up_cmd}` in a terminal on this \
             machine. I'll detect the join automatically."
        ));
    }

    let mut url_shown = false;
    for round in 0..3 {
        for tick in 0..90u32 {
            if let Ok(pair) = tailscale_identity() {
                if let Some(c) = child.as_mut() {
                    let _ = c.kill();
                }
                return Ok(pair);
            }
            if !url_shown {
                if let Some(url) = tailscale_auth_url() {
                    ctx.success("Open this link on ANY device to authenticate (it also handles account signup):");
                    ctx.raw(&format!("      {url}"));
                    url_shown = true;
                }
            }
            if tick % 15 == 14 {
                ctx.progress("waiting for the tailnet join\u{2026}");
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        if round < 2 && !ctx.asker.confirm("Still waiting on the join \u{2014} keep waiting?", true) {
            break;
        }
    }
    if let Some(c) = child.as_mut() {
        let _ = c.kill();
    }
    Err("tailnet join did not complete".into())
}

pub fn tailscale(ctx: &mut Ctx) -> bool {
    // Plain-language framing FIRST
    // they know what they're doing right from our onboarding"). Someone
    // with no Tailscale background must be able to answer the prompts.
    ctx.info("Noomesh runs on a tailnet — your own private network (Tailscale/WireGuard).");
    ctx.raw("    The dashboard is served at https://<your-machine>.<tailnet>.ts.net, and any");
    ctx.raw("    remote GPU/edge nodes you add later join the cluster over the same network.");
    ctx.raw("    No account yet? The login link this step opens takes signups (Google/GitHub/");
    ctx.raw("    Microsoft) — the free plan covers 100 devices, plenty for a personal cluster.");
    ctx.raw("    The wizard only changes settings after asking, and tells you where it did.");

    let mut installed = tailscale_installed();

    // Interactive remediation. Install and join hand the REAL terminal to
    // subprocesses (sudo password prompts, the `tailscale up` login URL) —
    // the console runs them directly, the TUI suspends/resumes around
    // them, and the web wizard (run_inherited → None) keeps the manual
    // path. This used to dead-end into "set it up later and re-run
    // 'noo onboard --reconfigure'"; the wizard can do both steps itself.
    let can_remediate = !ctx.non_interactive && !ctx.dry_run;

    if !installed && can_remediate
        && ctx.asker.confirm(
            "Tailscale is not installed. Install it now (official installer, may prompt for sudo)?",
            true,
        )
    {
        // Downloaded to a file, checked, digest printed, then run — never
        // piped into a shell. See crate::vendor.
        let ts_cmd = crate::vendor::install_script_cmd(crate::vendor::TAILSCALE_INSTALL_URL);
        ctx.info("Installing Tailscale from tailscale.com/install.sh (downloaded, checked, digest logged)");
        let code = ctx.ui.run_inherited(&["sh".into(), "-c".into(), ts_cmd]);
        installed = tailscale_installed();
        match code {
            None => ctx.warn(
                "This frontend can't run the installer itself — run the command above \
                 in a terminal, then continue here.",
            ),
            Some(0) if installed => {
                // Just installed: no peers depend on this daemon yet, so the
                // restart that applies the switch costs nothing. An existing
                // Tailscale is never restarted here (docs/security/telemetry.md).
                if ctx.ui.run_inherited(&["sh".into(), "-c".into(), crate::vendor::tailscale_nologs_linux_script()]) != Some(0) {
                    ctx.warn("Could not switch off tailscaled's log upload — see docs/security/telemetry.md, Host software.");
                }
            }
            _ => ctx.warn("Installer did not complete — continuing with the manual path below."),
        }
        installed = tailscale_installed();
    }

    let mut identity =
        if installed { tailscale_identity() } else { Err("tailscale is not installed".into()) };

    if identity.is_err() && installed && can_remediate {
        // Installed (possibly just now) but not joined. `--operator=$USER`
        // matters beyond the join: it is what lets the serve mapping below
        // (and future re-runs) work without sudo.
        let user = std::env::var("USER").unwrap_or_default();
        // Tailnet hostname is an IDENTITY choice, not an accident: a fresh
        // join silently took the OS hostname where the operator's
        // convention was a role name (host8 vs noo-controller,
        // 2026-09-01). Ask, defaulting to the machine name.
        let os_host = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|h| h.trim().to_string())
            .unwrap_or_default();
        // A CONTROLLER defaults to the ROLE name: the stable tailnet name is
        // the entire failover mechanism (nodes pin CONTROLLER_URL to it;
        // warm-standby promotion = the standby claims the name and the fleet
        // reconverges with zero per-node edits — operator doctrine,
        // 2026-09-01). Workers default to the machine name.
        let default_host = if ctx.state.mode == "controller" {
            ctx.info("Controllers should keep the ROLE name: nodes pin their controller by");
            ctx.info("tailnet name, so failover to a standby is just re-claiming the name.");
            "noo-controller".to_string()
        } else {
            os_host.clone()
        };
        let ts_hostname = ctx.asker.ask(
            &Prompt::new("Tailnet hostname for this machine (its <name>.<tailnet>.ts.net identity)")
                .default(default_host),
        );
        let mut argv: Vec<String> = vec!["sudo".into(), "tailscale".into(), "up".into()];
        if !user.is_empty() {
            argv.push(format!("--operator={user}"));
        }
        if !ts_hostname.trim().is_empty() && ts_hostname.trim() != os_host {
            argv.push(format!("--hostname={}", ts_hostname.trim()));
        }
        // Controllers claim their tag AT JOIN, the way enroll claims
        // tag:worker — an admin (autogroup:admin owns tag:controller in the
        // ACL the wizard prints) can advertise it directly, no API round
        // trip. host8 2026-09-01: joined untagged, then the API assertion
        // reported "did not take" with the real error discarded.
        let controller_tag = ctx.state.mode == "controller";
        if controller_tag {
            argv.push("--advertise-tags=tag:controller".into());
        }
        // noomesh never uses Tailscale SSH; the box joins with it off.
        argv.push("--ssh=false".into());
        let up_cmd = argv.join(" ");
        if ctx.asker.confirm(
            &format!(
                "Join your tailnet now? (runs `{up_cmd}`; opens a login link where you \
                 can also CREATE a free account)"
            ),
            true,
        ) {
            let mut result = ctx.ui.run_inherited(&argv);
            if controller_tag && matches!(result, Some(c) if c != 0) {
                // The login identity is not a tag owner (non-admin account):
                // join untagged and let ensure_controller_tag take the API /
                // console path with a clear message.
                ctx.warn("tailscale refused --advertise-tags=tag:controller (this login is not a tag owner) — joining untagged; the tag is asserted next step.");
                argv.retain(|a| !a.starts_with("--advertise-tags="));
                result = ctx.ui.run_inherited(&argv);
            }
            match result {
                Some(0) => identity = tailscale_identity(),
                // No terminal to hand over (web): AuthURL-assisted join
                // with automatic detection instead of a dead end.
                None => identity = assisted_join(ctx, &up_cmd),
                _ => ctx.warn("`tailscale up` did not complete — continuing with the manual path below."),
            }
            // The web frontend user may have joined out-of-band just now.
            if identity.is_err() {
                identity = tailscale_identity();
            }
        }
    }

    let (dns, ip) = match identity {
        Ok(pair) => pair,
        Err(why) => {
            ctx.error(&format!("Tailscale unavailable: {why}"));
            ctx.raw("    Without Tailscale, the dashboard is reachable only on this machine /");
            ctx.raw("    the local network, and the gateway cert will NOT carry a tailnet name.");
            ctx.raw("    To set it up later: install tailscale, 'tailscale up', then re-run");
            ctx.raw("    'noo onboard --reconfigure' so the gateway cert gains the tailnet SANs.");
            if ctx.non_interactive {
                ctx.warn("Non-interactive: continuing as a LAN-only install.");
            } else if !ctx.asker.confirm("Continue as a LAN-only install?", true) {
                ctx.state.interrupted = true;
                ctx.state.aborted = Some(super::Abort::Cancelled {
                    reason: "declined a LAN-only install; join the tailnet and re-run".into(),
                });
                ctx.info("Setup aborted — join the tailnet and re-run 'noo onboard'.");
                return false;
            }
            return true;
        }
    };

    ctx.success(&format!("Tailnet identity: {dns} ({ip})"));
    ctx.state.ts_dnsname = dns.clone();
    ctx.state.ts_ip = ip.clone();

    // Step 2 asked for the node IP BEFORE this join existed, so on a fresh
    // box it could only offer the LAN address. The tailnet IP is the one
    // other nodes actually reach this controller on — correct it now
    // (first-contact finding #1, 2026-08-20).
    if !ctx.dry_run {
        let prev = ctx.read_env("NODE_IP");
        if prev != ip {
            ctx.update_env("NODE_IP", &ip);
            ctx.info(&format!("NODE_IP updated {prev} → {ip} (tailnet address supersedes the pre-join LAN guess)"));
        }
    }

    // Tailnet feature detection — all read locally from the daemon, no
    // API key involved. Two settings make or break the dashboard story:
    // MagicDNS (the https://<name> URL) and HTTPS certificates (without
    // them `tailscale serve` fails, and the old error blamed permissions).
    let mut facts = tailnet_facts();
    for w in &facts.health {
        ctx.warn(&format!("tailscale reports: {w}"));
    }
    if !facts.magic_dns_enabled {
        ctx.warn("MagicDNS is disabled on your tailnet — the https://<name> URL won't resolve.");
        ctx.raw(&format!("    Enable it (one toggle): {TS_DNS_CONSOLE} \u{2192} \"Enable MagicDNS\""));
    }
    if !facts.cert_domains_enabled && !ctx.dry_run {
        ctx.warn("HTTPS certificates are not enabled on your tailnet.");
        ctx.raw("    'tailscale serve' needs them for the browser-trusted ts.net cert.");
        ctx.raw("    BRAND-NEW tailnet? Tailscale keeps its admin console behind the");
        ctx.raw("    welcome flow until a SECOND device joins — install the Tailscale");
        ctx.raw("    app on your phone (1 min) and the links below start working.");
        ctx.raw(&format!("    Enable it (one toggle): {TS_DNS_CONSOLE} \u{2192} \"Enable HTTPS\""));
        if !ctx.non_interactive {
            // Wait-and-recheck instead of failing later with a misleading
            // permissions error. The user flips the toggle in the console;
            // we poll the daemon until it shows up.
            for _ in 0..5 {
                if !ctx.asker.confirm("Enabled HTTPS in the admin console? Re-check now?", true) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
                facts = tailnet_facts();
                if facts.cert_domains_enabled {
                    ctx.success("HTTPS certificates enabled — continuing.");
                    break;
                }
                ctx.warn("Still disabled (the toggle can take a few seconds to propagate).");
            }
        }
        if !facts.cert_domains_enabled {
            // Fail FAST (first-contact finding #4): attempting the serve
            // mapping without certs wedged instead of erroring. Skip it
            // loudly with the manual recipe; --reconfigure re-runs this.
            ctx.warn("Skipping the tailscale serve mapping — HTTPS certificates are disabled.");
            ctx.raw("    After enabling HTTPS, either re-run `noo onboard --reconfigure` or apply manually:");
            let gw_port = 8080 + ctx.state.port_offset;
            ctx.raw(&format!("      sudo tailscale serve --bg https://{ip}:{gw_port}"));
            ctx.raw(&format!("      sudo tailscale serve --bg --set-path=/mcp/user https://{ip}:{gw_port}/mcp/user"));
            ctx.raw(&format!("      sudo tailscale serve --bg --set-path=/mcp/operator https://{ip}:{gw_port}/mcp/operator"));
            return true;
        }
    }

    // Serve mapping: browser → ts.net (public cert) → gateway HTTPS.
    // Written now — serve config is static and does not need the gateway
    // up; it starts proxying the moment the gateway is. The backend target
    // is the tailnet IP, not localhost, matching the gateway cert's SANs.
    //
    // A NAMED instance mounts under /<instance> (and
    // /<instance>/mcp) instead of claiming / and /mcp — one MagicDNS host
    // can front several stacks, each at its own path and offset port. The
    // default instance keeps / and /mcp exactly as before (with the port
    // still honoring a non-zero offset). tailscale serve strips the
    // set-path prefix before proxying, so the gateway sees the same
    // request shape either way.
    let inst = ctx.state.instance.clone();
    let gw_port = 8080 + ctx.state.port_offset;
    let plan = crate::tailnet_serve::Plan { ip: ip.to_string(), gw_port, instance: inst.clone() };
    let url_suffix = plan.root_path();
    let mcp_path = plan.door_paths().remove(0);
    if ctx.dry_run {
        ctx.dry(&format!(
            "tailscale serve --bg {}https://{ip}:{gw_port} (+ {mcp_path} → /mcp/user, {url_suffix}/mcp/operator → /mcp/operator)",
            if url_suffix.is_empty() { String::new() } else { format!("--set-path={url_suffix} ") },
        ));
        return true;
    }
    // One shared implementation with `noo controller promote`
    // (tailnet_serve.rs): every exit status checked, one operator-grant
    // retry on a permission failure (host8 fresh install, 2026-08-31),
    // and the failure reported with the command that failed.
    match crate::tailnet_serve::apply(&plan, ctx.non_interactive) {
        Ok(applied) => {
            if applied.granted_operator {
                if let Ok(user) = std::env::var("USER") {
                    ctx.info(&format!("Granted tailscale operator to {user} (one-time) — serve mapping written on retry."));
                }
            }
            ctx.state.ts_serve_applied = true;
            ctx.success(&format!("tailscale serve configured: https://{dns}{url_suffix} → gateway (+ /mcp/user, /mcp/operator)"));
            if !inst.is_empty() {
                ctx.info(&format!(
                    "Instance `{inst}` shares this host's MagicDNS name — dashboard at https://{dns}{url_suffix}, MCP at https://{dns}{mcp_path}."
                ));
            }
        }
        Err(f) => {
            // Two distinct causes, previously conflated into one wrong hint:
            // missing HTTPS certs (detected above) or a permissions failure
            // (serve needs root or the tailnet operator).
            if !facts.cert_domains_enabled {
                ctx.warn("Could not write the tailscale serve mapping — HTTPS certificates are disabled (see above).");
            } else {
                ctx.warn(&format!("Could not write the tailscale serve mapping — `{}` failed: {}", f.command, f.detail));
            }
            ctx.raw("    Apply it manually:");
            for line in plan.manual_lines() {
                ctx.raw(&format!("      {line}"));
            }
        }
    }

    // Persist the advertised self URL (host8 fresh install, 2026-08-31):
    // the example seeds `services.gateway_url` as localhost and no step
    // rewrote it, so enrollment blobs told every joining node to dial
    // localhost. The tailnet identity is established right here — write it,
    // independent of whether the serve mapping applied (the gateway is
    // directly reachable on :{gw_port} over the tailnet either way).
    if !dns.is_empty() {
        let advertised = format!("https://{dns}:{gw_port}");
        yamlcfg::update_yaml_gateway_url(ctx, &advertised);
        ctx.success(&format!("Advertised gateway URL → {advertised} (noomesh.yaml services.gateway_url)"));
    }

    // Enrollment (OAuth client capture) moved to the END of the security
    // step: it writes into secrets/env.sops, and the sops binary + store
    // only exist after Step 4's backend init — capturing here lost the
    // operator's pasted credentials (first-contact finding #6, 2026-08-20).
    true
}

/// Optional multi-node branch: collect a Tailscale OAuth
/// client into the sops store and declare `tag:worker` in the tailnet ACL
/// — the two admin-console detours that stood between "cluster up" and
/// push-button device enrollment (`noo cluster bootstrap-token create` →
/// one-liner on the node → `noo cluster provision <name> --wait`).
///
/// Contract (operator, 2026-08-10): every tailnet WRITE is
/// confirm-before + report-after with the admin-console link; declining
/// leaves the documented manual path.
fn tailscale_multinode(ctx: &mut Ctx) {
    if ctx.non_interactive || ctx.dry_run {
        return;
    }

    let store = crate::commands::secrets::SecretStore::load_sops(
        &ctx.repo_root.join("secrets/env.sops"),
    )
    .ok();
    let has_credential = store
        .as_ref()
        .map(|st| {
            st.contains("NOO_TAILSCALE_OAUTH_CLIENT_ID")
                || st.contains("NOO_TAILSCALE_API_KEY")
        })
        .unwrap_or(false);

    // Stored creds are PROBED, not trusted (finding #37, second half): the
    // console can hold several clients, and the stored one may be an older
    // under-granted paste — with NO user path to replace it, because this
    // prompt was skipped whenever creds existed (live 2026-08-25: console
    // showed a both-tags client, sops held an older one).
    let mut need_paste = !has_credential;
    if has_credential {
        let stored = store.as_ref().and_then(|st| {
            Some((
                st.value_for_provider_api("NOO_TAILSCALE_OAUTH_CLIENT_ID")?,
                st.value_for_provider_api("NOO_TAILSCALE_OAUTH_CLIENT_SECRET")?,
            ))
        });
        if let Some((id, secret)) = stored {
            ctx.progress("Verifying the stored OAuth client can mint worker join keys...");
            match crate::commands::cluster_provision::probe_worker_key_grant(
                id.trim(),
                secret.trim(),
            ) {
                Ok(()) => {
                    ctx.success("Stored OAuth client verified: tag:worker keys mint OK.")
                }
                Err(e) => {
                    ctx.warn(&format!("Stored OAuth client FAILED verification: {e}"));
                    ctx.raw("    Paste a client with BOTH tags below (generate one if needed):");
                    ctx.raw(&format!("      {TS_OAUTH_CONSOLE}"));
                    need_paste = true;
                }
            }
        }
    }
    if need_paste {
        if !has_credential && !ctx.asker.confirm(
            "Planning to add remote nodes (GPU boxes, edge devices) later? \
             Set up cluster enrollment now? (optional)",
            false,
        ) {
            ctx.info("Skipped — `noo cluster invite` will walk you through it when needed.");
            ctx.state.multinode = Some(false);
            return;
        }
        ctx.state.multinode = Some(true);
        ctx.info("One-time setup (ONE console visit, in this order — the OAuth form");
        ctx.info("refuses the key-write scope until the tags EXIST in your ACL):");
        ctx.raw("    1. ACL policy — paste into the tagOwners section (create it if absent):");
        ctx.raw(&format!("         {TS_ACL_CONSOLE}"));
        // RENDERED from config/tailscale-acl.hujson, never restated here.
        // This block used to be two hardcoded lines, and it drifted: the
        // declared file gained `tag:kiosk` in #172 and these lines did not,
        // so a fresh install pasted a policy missing a tag the CLI can write.
        // A hand-maintained copy of a declared file is a copy that drifts —
        // the same defect as a bridge nobody closes (186a) and a container
        // compose no longer defines (186b).
        //
        // tag:controller as CO-OWNER is load-bearing (finding #46): an OAuth
        // client acts AS its tags and can only mint keys for tags one of its
        // OWN tags owns — autogroup:admin authorizes the human in the console,
        // not the client doing the minting. That reason now lives beside the
        // owners in the declared file, where the value it explains lives.
        let declared_tags = crate::commands::tailnet_policy::declared_policy()
            .map(crate::commands::tailnet_policy::declared_tag_owners)
            .unwrap_or_default();
        if declared_tags.is_empty() {
            // Honest absence beats a stale literal that looks authoritative.
            ctx.warn(
                "this noo binary carries no embedded tailnet policy, so the tag list \
                 cannot be shown — copy tagOwners from config/tailscale-acl.hujson",
            );
        } else {
            ctx.raw("           \"tagOwners\": {");
            for (tag, owners) in &declared_tags {
                ctx.raw(&format!("               \"{tag}\": {owners},"));
            }
            ctx.raw("           },");
        }
        ctx.raw("    2. OAuth client — Generate, with scopes:");
        ctx.raw(&format!("         {TS_OAUTH_CONSOLE}"));
        ctx.raw("         \u{201C}Keys \u{2192} Auth Keys: write\u{201D} (select tag:worker + tag:controller)");
        ctx.raw("         \u{201C}Policy file: write\u{201D}");
        // Devices scope powers cleanup: worker teardown and the offboard
        // walk delete their own device records instead of stranding
        // <host>-1, -2, ... ghosts in the tailnet (finding #66).
        ctx.raw("         \u{201C}Devices \u{2192} Core: write\u{201D} (device cleanup on teardown/offboard)");
        ctx.raw("    3. Copy the client ID + secret back here.");
        ctx.raw("    (Unlike API keys with their 90-day expiry, the client secret does not");
        ctx.raw("    expire; Noomesh mints short-lived tokens from it per operation.)");

        let id = ctx
            .asker
            .ask(&super::prompt::Prompt::new("OAuth client ID (blank to skip)"));
        if id.trim().is_empty() {
            ctx.info("Skipped — set it up later via `noo cluster invite`.");
            return;
        }
        let secret = ctx
            .asker
            .ask(&super::prompt::Prompt::new("OAuth client secret").secret().required());
        match crate::commands::secrets::store_upsert(&[
            ("NOO_TAILSCALE_OAUTH_CLIENT_ID".to_string(), id.trim().to_string()),
            ("NOO_TAILSCALE_OAUTH_CLIENT_SECRET".to_string(), secret.trim().to_string()),
        ]) {
            Ok(()) => {
                ctx.success("OAuth client stored in secrets/env.sops (never .env).");
                // Verify-by-probe, not ceremony (finding #37): test-mint a
                // tag:worker key NOW — a client created before tag:worker
                // existed in the ACL silently lacks the grant, and the old
                // flow surfaced that days later at the first node with a
                // misleading error.
                ctx.progress("Verifying the client can mint worker join keys...");
                match crate::commands::cluster_provision::probe_worker_key_grant(
                    id.trim(),
                    secret.trim(),
                ) {
                    Ok(()) => {
                        ctx.success("OAuth client verified: tag:worker keys mint OK.");
                        // Converge the RUNTIME, not just the store (finding
                        // #42): the running gateway still holds the client
                        // it launched with — key minting happens gateway-
                        // side, so without a recreate the next
                        // bootstrap-token create fails on the OLD client.
                        // A plain restart keeps the old env; --force
                        // recreates with fresh secrets.
                        let gateway_running = {
                            let name = crate::envfile::container("gateway");
                            std::process::Command::new("docker")
                                .args(["ps", "-q", "--filter", &format!("name={name}")])
                                .output()
                                .map(|o| o.status.success() && !o.stdout.is_empty())
                                .unwrap_or(false)
                        };
                        if !gateway_running {
                            // Fresh birth: no stack yet — the coming launch
                            // loads this client anyway (finding #60: the
                            // offer no-op'd against a nonexistent network
                            // with a scary message).
                            ctx.info("Gateway not running yet — the upcoming launch will use this client.");
                        } else if ctx.asker.confirm(
                            "Recreate the gateway now so it uses this client? (it currently runs with the old one)",
                            true,
                        ) {
                            let code = sh::run_script_streamed(
                                ctx,
                                "noomesh-restart.sh",
                                &["--force", "gateway"],
                            );
                            if code == 0 {
                                ctx.success("Gateway recreated with the new OAuth client.");
                            } else {
                                ctx.warn("Gateway recreate failed — run: noo stack restart --force gateway");
                            }
                        } else {
                            ctx.info("Remember: `noo stack restart --force gateway` before minting join keys.");
                        }
                    }
                    Err(e) => {
                        ctx.warn(&format!("OAuth client verification FAILED: {e}"));
                        ctx.raw("    Fix in the console, then re-run this step (noo onboard --reconfigure):");
                        ctx.raw("      https://login.tailscale.com/admin/settings/oauth");
                    }
                }
                // Make the credential visible to ensure_tag_owner below in
                // THIS process (it resolves from the environment).
                std::env::set_var("NOO_TAILSCALE_OAUTH_CLIENT_ID", id.trim());
                std::env::set_var("NOO_TAILSCALE_OAUTH_CLIENT_SECRET", secret.trim());
            }
            Err(e) => {
                ctx.warn(&format!("Could not store the OAuth client: {e}"));
                return;
            }
        }
    }

    // ACL: both tags must be declared before a tagged join key can be
    // minted — and this box IS the controller, so the prompt names both
    // (finding #18). Probe first and only ASK when something is missing:
    // re-runs on a converged tailnet used to re-ask a question with nothing
    // to do (finding #25). Confirm-before-write is preserved for the case
    // that actually writes.
    // Controller FIRST: the fresh tag:worker stanza names tag:controller
    // as co-owner (finding #46), so the owner must exist before the owned.
    let missing: Vec<&str> = ["tag:controller", "tag:worker"]
        .into_iter()
        .filter(|t| {
            !matches!(crate::commands::cluster_provision::tag_owner_present(t), Ok(true))
        })
        .collect();
    if missing.is_empty() {
        ctx.success("tag:worker + tag:controller already declared in your ACL — nothing to change.");
        ctx.raw(&format!("    Review any time: {TS_ACL_CONSOLE}"));
    } else if ctx.asker.confirm(
        &format!(
            "Declare {} in your tailnet ACL now? (adds tagOwners entries as \
             [\"autogroup:admin\"] — required before join keys can be minted; \
             this machine is the controller)",
            missing.join(" + ")
        ),
        true,
    ) {
        for tag in missing {
            match crate::commands::cluster_provision::ensure_tag_owner(tag) {
                Ok(crate::commands::cluster_provision::TagOwnerOutcome::AlreadyPresent) => {
                    ctx.success(&format!("{tag} is already declared in your ACL."));
                }
                Ok(crate::commands::cluster_provision::TagOwnerOutcome::Added) => {
                    ctx.success(&format!("{tag} added to your tailnet ACL."));
                }
                Err(e) => {
                    ctx.warn(&format!("ACL update for {tag} failed: {e}"));
                    ctx.raw("    Add it manually in the policy editor:");
                    ctx.raw(&format!("      \"tagOwners\": {{ \"{tag}\": [\"autogroup:admin\"] }}"));
                    ctx.raw(&format!("      {TS_ACL_CONSOLE}"));
                }
            }
        }
        ctx.raw(&format!("    Review any time: {TS_ACL_CONSOLE}"));
    }

    // The tags above let a join key be MINTED; the grants are what let a
    // tagged node REACH the controller. Onboarding used to stop at the tags,
    // so a port grant the declaration carried never reached a tailnet — the
    // controller's :8083 cache port was unreachable from every node until
    // someone added it by hand. An additive merge fills the gap without
    // touching anything the operator already has: their own groups, tags,
    // grants and ssh rules stay as they are, which is what makes it safe to
    // offer on a tailnet noomesh does not own. A wholesale push is never
    // offered here.
    tailnet_grants_merge(ctx);

    // The PULL flow is the way nodes are added now — the old
    // mint-join-key → SSH-provision recipe here confused a live run (#26).
    ctx.info("Adding a node later (no SSH): `noo cluster bootstrap-token create --node <name>`");
    ctx.raw("    \u{2192} run the printed one-liner on the node \u{2192} `noo cluster provision <name> --wait`.");
}

/// Ensure the grants noomesh declares exist in the live tailnet policy,
/// adding only what is missing. See `commands::tailnet_merge`.
fn tailnet_grants_merge(ctx: &mut Ctx) {
    if ctx.dry_run {
        ctx.dry("check the tailnet policy for noomesh's grants and ADD any that are missing (additive; nothing removed)");
        return;
    }
    ctx.progress("Checking your tailnet policy for the grants noomesh needs...");
    let (merged, plan) = match crate::commands::tailnet_policy::plan_merge() {
        Ok(x) => x,
        Err(e) => {
            ctx.warn(&format!("Could not read the tailnet policy to check its grants: {e}"));
            ctx.raw("    Check later: noo security tailnet policy   (add what's missing with --merge)");
            return;
        }
    };
    if plan.is_empty() {
        ctx.success("Your tailnet policy already has every grant noomesh needs.");
        return;
    }
    ctx.info("Your tailnet policy is missing some of what noomesh needs:");
    for l in crate::commands::tailnet_policy::plan_lines(&plan) {
        ctx.raw(&format!("      {l}"));
    }
    ctx.raw("    Nothing is removed — your own groups, tags, grants and ssh rules are kept as they are.");
    // Unattended: never write someone's tailnet policy without a person
    // saying so. Print the plan and the command instead.
    if ctx.non_interactive {
        ctx.info("Not applied in a non-interactive run. Apply with: noo security tailnet policy --merge");
        return;
    }
    if !ctx.asker.confirm("Add these to your tailnet policy now?", true) {
        ctx.info("Skipped. Apply any time with: noo security tailnet policy --merge");
        return;
    }
    match crate::commands::cluster_provision::push_acl(&merged) {
        Ok(backup) => {
            ctx.success("Grants added to your tailnet policy.");
            ctx.raw(&format!("    Previous policy backed up to {}", backup.display()));
        }
        Err(e) => {
            ctx.warn(&format!("Adding the grants failed: {e}"));
            ctx.raw("    Retry with: noo security tailnet policy --merge");
        }
    }
}

/// Step: SECRETS (finding #16, operator design 2026-08-20). Split out of the
/// old monolithic security step and moved BEFORE tailscale: credential
/// generation + the sops/age store have ZERO tailnet dependencies, so sops
/// failures surface before the operator invests admin-console time, and the
/// store exists for everything downstream (enrollment, channel tokens).
/// The tailnet-dependent half (certs with SANs, CA trust, enrollment) is
/// pki_enrollment() below.
/// The security step. Returns false — and mints NOTHING — when the encrypted
/// store could not be armed: the wizard stops there (`run_all`).
pub fn secrets_setup(ctx: &mut Ctx) -> bool {
    ctx.info("Securing the cluster: encryption keys, secret store, admin account.");

    // Ensure secrets dir (0700)
    if !ctx.dry_run {
        if let Err(e) = std::fs::create_dir_all(&ctx.secrets_dir) {
            ctx.warn(&format!("could not create secrets dir: {e}"));
        } else {
            let _ = std::fs::set_permissions(&ctx.secrets_dir, std::fs::Permissions::from_mode(0o700));
        }
    }

    // Restore an EXISTING store first (fresh install, kept credentials —
    // the recommended reinstall shape; operator, 2026-09-01: "why do we do
    // this manually"). Offered only when no store exists yet; the pasted
    // file is copied and decrypt-verified against the age key before
    // anything else runs, so a wrong path or missing key fails HERE with
    // its real name, not three steps later as mystery re-mints.
    let store_path = ctx.secrets_dir.join("env.sops");
    if !ctx.dry_run && !ctx.non_interactive && !store_path.exists() {
        let candidate = ctx.asker.ask(
            &Prompt::new("Restore an existing secret store? Path to env.sops (Enter = mint fresh)")
                .default(String::new()),
        );
        let candidate = candidate.trim().to_string();
        if !candidate.is_empty() {
            let expanded = if let Some(rest) = candidate.strip_prefix("~/") {
                format!("{}/{rest}", std::env::var("HOME").unwrap_or_default())
            } else {
                candidate.clone()
            };
            match std::fs::copy(&expanded, &store_path) {
                Err(e) => ctx.warn(&format!("could not copy {expanded}: {e} — minting fresh instead")),
                Ok(_) => {
                    let _ = std::fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o600));
                    let count = Command::new("bash")
                        .arg("-c")
                        .arg(format!(
                            "sops -d --input-type dotenv --output-type dotenv '{}' 2>/dev/null | grep -c '^[A-Z_0-9]*='",
                            store_path.display()
                        ))
                        .output()
                        .ok()
                        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().ok())
                        .unwrap_or(0);
                    if count > 0 {
                        ctx.success(&format!(
                            "Secret store restored: {count} keys decrypt with the age key at {}",
                            crate::age_key::path().display()
                        ));
                    } else {
                        let _ = std::fs::remove_file(&store_path);
                        ctx.warn("The restored store did NOT decrypt (wrong file, or the age key is absent) — removed; minting fresh.");
                        ctx.raw(&format!(
                            "    (Restore the matching age key to {} and re-run --only secrets.)",
                            crate::age_key::default_path().display()
                        ));
                    }
                }
            }
        }
    }

    // Secrets at rest (SOPS+age) — FIRST, before a single value is minted.
    // It used to run at the END of this step: every credential below was
    // written to plaintext .env, and the whole file encrypted afterwards —
    // so a missing or failing init script left all of them in the clear and
    // the wizard still finished green. With the store armed here,
    // `Ctx::update_env` routes every credential straight into it, and a
    // store that cannot be armed stops the wizard with nothing minted.
    if !arm_secret_store(ctx) {
        return false;
    }
    // Provider keys the environment step collected before the store existed
    // (it runs one step earlier): into the store now, never into .env.
    for (k, v) in std::mem::take(&mut ctx.state.pending_secrets) {
        ctx.update_env(&k, &v);
    }

    // Admin account
    // The account exists when its password is in the store (the store is
    // armed above, before anything is minted). A legacy `secrets/admin_password.txt` — the bcrypt
    // hash the wizard used to write and nothing ever read — still counts, so
    // an install that predates its removal is not asked to make a new admin.
    let admin_file = ctx.secrets_dir.join("admin_password.txt");
    let admin_exists = ctx.secret_present("NOO_ADMIN_PASSWORD") || admin_file.exists();
    let admin_user_env = std::env::var("NOO_ADMIN_USER")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| ctx.read_env("NOO_ADMIN_USER"));

    let (admin_user, admin_pw): (String, Option<String>) = if admin_exists && !admin_user_env.is_empty() {
        ctx.info(&format!("Admin account already exists (user: {admin_user_env})"));
        (admin_user_env.clone(), None)
    } else if ctx.non_interactive {
        // Never printed: --ci runs under CI, and its stdout is a log that
        // outlives the run. The value goes to the store like every other
        // credential; the backup passphrases have had this treatment since
        // #128, and the admin password did not.
        let pw = util::token_urlsafe(16);
        // It is never shown, and not readable afterwards either: `secrets
        // reveal` refuses it by design. To log
        // in, the operator replaces it — the new value is shown once, from a
        // terminal, and nothing that was never shown is ever read back out.
        ctx.warn("Admin password auto-generated and stored encrypted — never printed. To log in, set a new one from a terminal you are sitting at:");
        ctx.raw("    noo security admin-password reset");
        ("admin".to_string(), Some(pw))
    } else {
        let user = ctx.asker.ask(&Prompt::new("Admin username").default("admin"));
        let pw = loop {
            let p1 = ctx.asker.ask(&Prompt::new("Admin password").secret().required());
            if let Some(why) = weak_password(&p1, &user) {
                ctx.warn(why);
                continue;
            }
            let p2 = ctx.asker.ask(&Prompt::new("Confirm password").secret().required());
            if p1 != p2 {
                ctx.warn("Passwords do not match.");
                continue;
            }
            break p1;
        };
        (user, Some(pw))
    };
    ctx.state.admin_username = admin_user.clone();
    if let Some(p) = &admin_pw {
        ctx.state.admin_password = p.clone(); // in-memory only; see State docs
    }

    // Generate / preserve secrets
    ctx.progress("Generating security credentials...");
    // Each credential has ONE home: the encrypted store (or .env on the env
    // backend, and on a fresh install for the one step before the store is
    // armed). The wizard used to also write `secrets/<name>.txt` and use the
    // file's existence as "already configured" — so every install carried
    // sixteen credentials in the clear beside env.sops, permanently, and
    // the wizard could not stop writing them without forgetting its own
    // install. Presence is now read from the store. A legacy
    // file is READ once, carried into the store, and offered for shredding
    // below — never rewritten, never silently deleted.
    for (name, env_var) in SECRETS {
        if ctx.secret_present(env_var) {
            ctx.info(&format!("{name} already exists (kept)"));
            continue;
        }
        let legacy = ctx.secrets_dir.join(format!("{name}.txt"));
        let carried = std::fs::read_to_string(&legacy).map(|s| s.trim().to_string()).unwrap_or_default();
        if !carried.is_empty() {
            ctx.update_env(env_var, &carried);
            ctx.info(&format!("{name} carried over from secrets/{name}.txt (offered for shredding below)"));
        } else if ctx.dry_run {
            ctx.dry(&format!("generate {name} → {env_var} (encrypted store only, no plaintext file)"));
        } else {
            // Every NATS password is interpolated into the server's own
            // config by nats-server, whose parser types bare values — a
            // leading digit parses as a number and the rest becomes a fatal
            // "Parse error on line 1". Alphanumeric with a leading letter
            // for all of them; the rest keep the denser alphabet.
            let val = if name.starts_with("nats_") {
                util::token_alnum(40)
            } else {
                util::token_urlsafe(32)
            };
            ctx.update_env(env_var, &val);
            ctx.success(&format!("{name} generated"));
        }
    }

    // Admin account → env. The gateway reads NOO_ADMIN_PASSWORD itself
    // (routes/core.rs); the bcrypt file the wizard used to write beside it
    // had no reader.
    if let Some(pw) = &admin_pw {
        if ctx.dry_run {
            ctx.dry("set NOO_ADMIN_USER/PASSWORD/GRAFANA_PASSWORD (encrypted store only, no plaintext file)");
        }
        ctx.update_env("NOO_ADMIN_USER", &admin_user);
        ctx.update_env("NOO_ADMIN_PASSWORD", pw);
        // Grafana is a separate trust boundary (its own login page, its own
        // users table, reachable on its own port) — it does not get the
        // operator's password. One leak must not open both doors.
        ctx.update_env("GRAFANA_PASSWORD", &util::token_urlsafe(24));
        ctx.success("Admin account configured");
    } else {
        ctx.info("Admin account unchanged");
    }

    // A re-run that leaves the admin account alone must still repair a
    // PLACEHOLDER Grafana password. `.env.example` shipped
    // `changeme` and `scripts/cluster-init.sh` wrote `admin`, so an install
    // bootstrapped either way has an admin UI whose password is published in
    // this repository — and the branch above never touches it, because the
    // operator answered "keep my account". This is the one place that sees
    // such an install again.
    //
    // Grafana copied the old value into its OWN database on first boot, so
    // rewriting the env var does not change the login. Say so rather than
    // implying the problem is now fixed.
    let existing_grafana = ctx.read_env("GRAFANA_PASSWORD");
    if crate::commands::security_local::is_published_placeholder(&existing_grafana) {
        if ctx.dry_run {
            ctx.dry("replace the placeholder GRAFANA_PASSWORD with a generated value");
        } else {
            ctx.update_env("GRAFANA_PASSWORD", &util::token_urlsafe(24));
        }
        ctx.warn(&format!(
            "GRAFANA_PASSWORD was the published placeholder '{}' — replaced with a generated value",
            existing_grafana.trim()
        ));
        ctx.raw("    Grafana copied the old one into its own database on first boot:");
        ctx.raw("    change it in Grafana too (Administration → Users → admin), or reset with");
        ctx.raw("    `docker exec noo-grafana grafana cli admin reset-admin-password <new>`.");
    }

    // Per-system DB role passwords: the migrations create
    // noo_app / noo_trellion / noo_trellion_ddl (+ noo_evolve under pro)
    // WITH these passwords, and compose interpolates them into the
    // gateway/trellion env. Existing installs carry them in sops, which is
    // why their absence here was invisible until the first true fresh
    // rehearsal (sandbox, 2026-08-06 — defect #12). Deliberately NOT part
    // of SECRETS/is_configured: pre-proposal-19 installs have no such
    // files and must not flip to "unconfigured".
    for (name, env_var) in [
        ("noo_app_db_password", "NOO_APP_DB_PASSWORD"),
        ("noo_trellion_db_password", "NOO_TRELLION_DB_PASSWORD"),
        ("noo_trellion_ddl_password", "NOO_TRELLION_DDL_PASSWORD"),
        ("noo_evolve_db_password", "NOO_EVOLVE_DB_PASSWORD"),
    ] {
        // A value already present (store, .env, or the process env) wins.
        if ctx.secret_present(env_var) || !std::env::var(env_var).unwrap_or_default().is_empty() {
            continue;
        }
        let legacy = ctx.secrets_dir.join(format!("{name}.txt"));
        let carried = std::fs::read_to_string(&legacy).map(|s| s.trim().to_string()).unwrap_or_default();
        if !carried.is_empty() {
            ctx.update_env(env_var, &carried);
            ctx.info(&format!("{name} carried over from secrets/{name}.txt (offered for shredding below)"));
        } else if ctx.dry_run {
            ctx.dry(&format!("generate {name} → {env_var} (encrypted store only, no plaintext file)"));
        } else {
            let val = util::token_urlsafe(32);
            ctx.update_env(env_var, &val);
            ctx.success(&format!("{name} generated"));
        }
    }

    // The audit log's signing key — the only one: without it every security
    // audit row is refused. Deliberately NOT part of SECRETS/is_configured,
    // for the same reason as the DB role passwords above. An install that
    // predates it gets it here on `--reconfigure`, or from `noo upgrade
    // --stack` (upgrade.rs reconcile_audit_key); its first gateway boot with the key
    // writes the checkpoint that hands the old rows over, so minting it late
    // costs no history.
    if !ctx.secret_present("NOO_AUDIT_HMAC_KEY")
        && std::env::var("NOO_AUDIT_HMAC_KEY").unwrap_or_default().is_empty()
    {
        if ctx.dry_run {
            ctx.dry("generate audit_hmac_key → NOO_AUDIT_HMAC_KEY (encrypted store only, no plaintext file)");
        } else {
            let val = util::token_urlsafe(32);
            ctx.update_env("NOO_AUDIT_HMAC_KEY", &val);
            ctx.success("audit_hmac_key generated");
        }
    }

    // The bus-principal keys, one per audience: the gateway
    // MACs every worker.* message with each, and each verifier holds only its
    // own. All three on every install, so turning an add-on on later never
    // needs the gateway recreated to learn its key. Same shape as the audit
    // key: not part of SECRETS/is_configured; `noo upgrade --stack`
    // (upgrade.rs reconcile_bus_keys) mints them on an older install.
    for key in crate::commands::upgrade::PER_SERVICE_KEYS {
        if ctx.secret_present(key) || !std::env::var(key).unwrap_or_default().is_empty() {
            continue;
        }
        if ctx.dry_run {
            ctx.dry(&format!("generate {key} (encrypted store only, no plaintext file)"));
        } else {
            ctx.update_env(key, &util::token_urlsafe(32));
            ctx.success(&format!("{key} generated"));
        }
    }

    // Backup encryption passphrases. The controller
    // backup refuses to run without these — it will not write a plaintext
    // dump, and it will not write a plaintext copy of the age private key,
    // which is what it did every six hours on every box until 2026-09-11
    // because the passphrases were "optional" and nothing ever set them.
    // "Optional" is how a box ends up with no encryption at all.
    //
    // Deliberately NOT part of SECRETS/is_configured, for the same reason as
    // the DB role passwords above: an install that predates this has no such
    // files and must not flip to "unconfigured".
    //
    // The two MUST differ. NOO_BACKUP_PASSPHRASE lives in env.sops; if it
    // also protected the age-key backup, recovery would be circular — you
    // would need the age key to read the passphrase that decrypts the age
    // key. Generated independently here, and backup-controller.sh refuses if
    // they are ever made equal.
    //
    // The backup-passphrase change: these two are NOT written to `secrets/<name>.txt` any more.
    //
    // The wizard used to write the plaintext and then warn the operator to
    // copy it into a password manager. Nothing removed the file afterwards,
    // and no check reported it, so on every controller ever onboarded the
    // passphrase protecting the age-key backup — the key to every other
    // secret — sat in the clear in the repo, indefinitely. The warning was
    // load-bearing and the filesystem was permanent; that is the wrong way
    // round. The value now has exactly two homes: the encrypted store, and
    // whatever the operator puts it in after reading it off this screen.
    let mut minted: Vec<(&str, String)> = Vec::new();
    for (name, env_var) in [
        ("backup_passphrase", "NOO_BACKUP_PASSPHRASE"),
        ("age_backup_passphrase", "NOO_AGE_BACKUP_PASSPHRASE"),
    ] {
        if !ctx.read_env(env_var).is_empty() || !std::env::var(env_var).unwrap_or_default().is_empty() {
            continue;
        }
        // A legacy plaintext file is still READ — a box onboarded before this
        // change keeps its passphrase, because rotating it silently would
        // orphan every backup already taken with it. It is reported and
        // offered for shredding below, not ignored and not deleted behind the
        // operator's back.
        let file = ctx.secrets_dir.join(format!("{name}.txt"));
        let existing = std::fs::read_to_string(&file).map(|s| s.trim().to_string()).unwrap_or_default();
        if !existing.is_empty() {
            ctx.update_env(env_var, &existing);
            ctx.info(&format!("{name} already exists (kept)"));
        } else if ctx.dry_run {
            ctx.dry(&format!("generate {name} → {env_var} (encrypted store only, no plaintext file)"));
        } else {
            let val = util::token_urlsafe(32);
            ctx.update_env(env_var, &val);
            ctx.success(&format!("{name} generated"));
            minted.push((env_var, val));
        }
    }
    if !minted.is_empty() {
        hand_over_backup_passphrases(ctx, &minted);
    }
    offer_to_shred_legacy_plaintext_files(ctx);

    // Auth + strict cluster-token verification are always on (invariants
    // since config-graduation phase 1) — no env knobs to write.
    // The gateway and the workers each present their OWN bus
    // user, and there is NO shared user on the server at all — the renderer
    // cannot emit one since an earlier release retired it (and `NATS_USER` /
    // `NATS_PASSWORD` with it: nothing writes, delivers or reads them).
    ctx.update_env("NATS_GATEWAY_USER", "gateway");
    ctx.update_env("NATS_WORKER_USER", "worker");
    render_nats_users(ctx);

    ctx.success("Secrets configured (encrypted at rest).");
    true
}

/// Hand the freshly minted backup passphrases to the person running the
/// wizard, once, and make them say they stored them.
///
/// This is the whole point of the backup-passphrase change. The passphrases have no consumer on
/// this box — `backup-controller.sh` reads them from the environment, and the
/// operator needs them on a DIFFERENT machine, months later, during a
/// restore. So there is exactly one moment when handing them over is cheap:
/// now, while the person who owns the box is looking at it.
///
/// The reveal only happens on the plain console with a real terminal on both
/// ends ([`WizardUi::reveal_secret`] returns false everywhere else). The TUI
/// would have the value overwritten by the next redraw, and the web wizard
/// would put it on an HTTP response — neither is a place to print the key to
/// the key. Those frontends, and `--non-interactive`, get the command to run
/// later instead, which is the same command and the same guard.
fn hand_over_backup_passphrases(ctx: &mut Ctx, minted: &[(&str, String)]) {
    ctx.warn(
        "Backup passphrases generated. NOO_AGE_BACKUP_PASSPHRASE is the key to the key: it \
         protects the age private key that opens EVERY other secret, and it is itself stored in \
         env.sops, which that same age key decrypts. On this box that is fine; once this box is \
         gone it is worthless. It is NOT written to any file — see \
         docs/operating/runbooks/backup-restore-secrets.md.",
    );

    // Deliberately NOT `.all(..)`: `all` short-circuits, and a frontend that
    // refused the FIRST value would silently skip the second. Both passphrases
    // are shown or the fallback covers both.
    let mut shown = !ctx.non_interactive
        && super::prompt::stdin_is_tty()
        && super::prompt::stdout_is_tty();
    if shown {
        for (k, v) in minted {
            shown &= ctx.ui.reveal_secret(k, v);
        }
    }

    if !shown {
        // No terminal to print to (or a frontend that must not). Say so, and
        // hand over the verb — NOT a file. An onboard that cannot show the
        // value must leave the operator able to get it, not leave a copy on
        // disk for them to find.
        ctx.warn("Not shown here: this wizard has no private terminal to print them on.");
        for (k, _) in minted {
            ctx.raw(&format!("    noo security secrets reveal {k}"));
        }
        ctx.warn(
            "Run those on the controller, from a terminal you are sitting at, and store both \
             values off this machine BEFORE the first backup runs.",
        );
        return;
    }

    // Shown. Now make it stick: an unanswered "please store this" is how the
    // old warning failed. Asked twice, because the first "y" is reflex.
    loop {
        if ctx.asker.confirm("Stored both in a password manager OFF this machine", false) {
            ctx.success("Backup passphrases handed over (no plaintext copy on this box).");
            return;
        }
        ctx.warn(
            "Without them, an encrypted backup is an opaque blob and this controller cannot be \
             rebuilt from it.",
        );
        if !ctx.asker.confirm("Continue anyway (you can re-read them later with 'noo security secrets reveal')", false) {
            continue;
        }
        for (k, _) in minted {
            ctx.raw(&format!("    noo security secrets reveal {k}"));
        }
        ctx.warn("Continuing WITHOUT the passphrases stored. Do it before the first backup runs.");
        return;
    }
}

/// A box onboarded before the backup-passphrase change still has `secrets/*_passphrase.txt` in the
/// clear. Report it and offer to shred it — after checking the value is
/// actually recoverable from the store, because shredding the only copy of a
/// passphrase is the one failure mode worse than leaving it on disk.
/// Every plaintext file an older wizard left in `secrets/` — the two backup
/// passphrases and, since, the sixteen credentials the
/// wizard wrote on every install. Each is offered for shredding only when
/// the value it holds is readable from somewhere else; a file that might be
/// the only copy is named and left alone.
fn offer_to_shred_legacy_plaintext_files(ctx: &mut Ctx) {
    use crate::commands::secrets_reveal::{LEGACY_PLAINTEXT_FILES, PLAINTEXT_PASSPHRASE_FILES};
    for (env_var, rel) in LEGACY_PLAINTEXT_FILES {
        let path = ctx.repo_root.join(rel);
        if !path.exists() {
            continue;
        }
        if ctx.dry_run {
            ctx.dry(&format!("offer to shred {rel} (plaintext {env_var})"));
            continue;
        }
        ctx.warn(&format!(
            "{rel} holds {env_var} in plaintext — a copy this install no longer needs and no \
             longer creates."
        ));
        // Refuse to shred what we cannot read back: a non-empty read from
        // the store or .env means the value survives the shred. The admin
        // file is a bcrypt HASH of NOO_ADMIN_PASSWORD, so "readable" for it
        // means the password itself is stored. A RETIRED credential has no
        // reader to lose, so it is offered for shredding either way.
        if !ctx.secret_present(env_var) && crate::commands::secrets::retired_store_key(env_var).is_none() {
            ctx.warn(&format!(
                "NOT offering to shred it: {env_var} is not in the store, so this file may be the \
                 only copy. Read it, store it off-box, then remove it by hand."
            ));
            continue;
        }
        // Passphrases are for a HUMAN; the rest have a process reader and
        // nobody needs to write them down.
        if PLAINTEXT_PASSPHRASE_FILES.iter().any(|(k, _)| k == env_var) {
            ctx.raw(&format!("    noo security secrets reveal {env_var}   # read it once, store it off-box"));
        }
        if ctx.non_interactive
            || !ctx.asker.confirm(&format!("Shred {rel} now"), false)
        {
            ctx.warn(&format!(
                "{rel} left in place — 'noo security scan' reports it as CRITICAL; \
                 'noo security secrets absorb-files' shreds every such file it can verify."
            ));
            continue;
        }
        match crate::commands::secrets_reveal::shred_file(&path) {
            Ok(()) => ctx.success(&format!("{rel} shredded")),
            Err(e) => ctx.error(&format!("could not shred {rel}: {e}")),
        }
    }
}

/// Render `monitoring/nats/users.conf` so the server is born knowing the
/// per-principal users. On a FRESH install there are no
/// nodes: none exist yet at onboard time, and each node's own credential is
/// minted when it is provisioned.
///
/// # Why a re-run must not render an empty node list
///
/// `users.conf` is written WHOLE. Passing no nodes on a controller that has
/// a fleet does not write a smaller file, it writes a file that authorises
/// gateway and worker and NOBODY ELSE — every node agent then fails bus auth
/// at the next HUP or recreate. `render_all` carries that warning for
/// `noo cluster provision`; onboard passed a hardcoded `&[]` and was the one
/// render path that could do it by simply being run twice.
///
/// So the node list is `whatever users.conf already authorises` ∪ `the
/// registry`, and the floor comes first deliberately: the secrets step runs
/// four steps before services, so "the gateway did not answer" is a normal
/// state here and must never be read as "there are no nodes". Passwords are
/// reused from the store (`principals_for` is reuse-or-mint), so this
/// rotates nothing.
///
/// Runs AFTER `arm_secret_store`, because the render reads the sops
/// store to reuse an existing password rather than rotating it — that
/// idempotence is what lets `noo cluster provision` re-render later without
/// changing the gateway's or the workers' credential.
///
/// # No shared user, and why a failure here is FATAL
///
/// A fresh install is born without the shared `noo` credential: the
/// renderer never emits it
/// with `--drop-legacy` while every other render path kept a bus-wide
/// `>`/`>` user nobody remembered to drop — tracker N8).
///
/// This step used to warn and continue, on the reasoning that "the stack
/// still starts on the shared user". That was the bug: the outcome of a
/// failed security step was a working stack with the security off, which is
/// the one outcome nobody inspects. It now aborts the onboard. The
/// committed baseline `users.conf` authenticates nobody, so a stack brought
/// up past this failure would not silently run open either — it would fail
/// at the first client connect.
fn render_nats_users(ctx: &mut Ctx) {
    use crate::commands::nats_users as nu;
    let repo = crate::envfile::repo_root();
    // The floor: who the file authorises right now. Read before the dry-run
    // return so the PLAN names the nodes it is going to keep — a dry run
    // whose line said "gateway + worker" was exactly the reassurance that
    // hid this.
    let existing = std::fs::read_to_string(repo.join(nu::USERS_CONF)).unwrap_or_default();
    let mut nodes = nu::node_users_in_conf(&existing);
    if let Some(doc) = crate::http::get_json_opt(ctx.g, "/api/cluster/nodes", true, 10) {
        for n in nu::nodes_from_registry(&doc) {
            if !nodes.iter().any(|x| x.eq_ignore_ascii_case(&n)) {
                nodes.push(n);
            }
        }
        nodes.sort();
    }
    let kept = if nodes.is_empty() {
        String::new()
    } else {
        format!(" + {} node principal(s) preserved: {}", nodes.len(), nodes.join(", "))
    };
    if ctx.dry_run {
        ctx.dry(&format!(
            "render monitoring/nats/users.conf (gateway + worker{kept}; NO legacy user)"
        ));
        return;
    }
    match nu::render_to(&repo, &nodes, &[]) {
        Ok(out) => ctx.success(&format!(
            "NATS users rendered ({} principals, no shared user){kept}",
            out.users
        )),
        Err(e) => {
            ctx.error(&format!("Could not render monitoring/nats/users.conf: {e}"));
            ctx.raw(
                "    Onboarding stops here deliberately. Without this file the bus has no\n    \
                 per-principal users, and the committed baseline authenticates nobody — so\n    \
                 continuing would produce a stack that cannot talk to its own broker.\n    \
                 Fix the cause (usually the sops store: `noo security secrets audit`),\n    \
                 then re-run `noo onboard`.",
            );
            std::process::exit(1);
        }
    }
}
/// The port the gateway serves on, as the gateway itself resolves it.
fn gateway_port() -> String {
    std::env::var("GATEWAY_PORT").unwrap_or_else(|_| "8080".to_string())
}

/// Record the controller's own gateway URL at the CLI's enrollment rung.
///
/// Root-owned and world-readable (644), matching what `prep-host.sh` writes
/// on a node: every user on the box runs `noo`, and the URL is not a secret.
/// Written via `sudo tee` because the wizard runs as the operator, and the
/// same consent posture as the rest of its privileged steps applies.
fn write_controller_url(url: &str, may_prompt: bool) -> Result<(), String> {
    let ok = sudo_cmd(may_prompt)
        .args(["install", "-d", "-m", "755", "/etc/noo"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return Err("could not create /etc/noo".into());
    }
    // `sudo tee` with the URL on STDIN, not `sh -c` with a redirect: the
    // redirect would be performed by the invoking shell, which is not root,
    // and routing the value through a shell string invites a quoting bug in
    // the one place a quoting bug would write the wrong URL.
    use std::process::Stdio;
    let mut child = sudo_cmd(may_prompt)
        .args(["tee", ENROLLED_CONTROLLER_URL])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn tee: {e}"))?;
    if let Some(mut si) = child.stdin.take() {
        crate::child_stdin::write_child_stdin(&mut si, format!("{url}\n").as_bytes())
            .map_err(|e| format!("write: {e}"))?;
    }
    let ok = child.wait().map(|s| s.success()).unwrap_or(false);
    if ok {
        let _ = sudo_cmd(may_prompt)
            .args(["chmod", "644", ENROLLED_CONTROLLER_URL])
            .status();
    }
    if ok { Ok(()) } else { Err("write failed".into()) }
}


/// Step: PKI & ENROLLMENT — the tailnet-dependent half of the old security
/// step: the gateway cert's SANs need the MagicDNS name + tailnet IP, so
/// this MUST run after the tailscale join; enrollment needs the sops store
/// secrets_setup() created (finding #6's dependency, now structural).
pub fn pki_enrollment(ctx: &mut Ctx) {
    // PKI (native)
    ctx.progress("Generating TLS certificates...");
    ensure_pki(ctx);
    grafana_door(ctx);

    // CA trust
    ctx.progress("Installing cluster CA into trust store...");
    install_ca_trust(ctx);

    // Tighten .env perms
    if !ctx.dry_run {
        let _ = std::fs::set_permissions(&ctx.env_path, std::fs::Permissions::from_mode(0o600));
    }

    ctx.state.security_configured = true;
    // Cluster enrollment (OAuth client): structurally after BOTH of its
    // dependencies now — the sops store (secrets step) and the tailnet
    // identity (tailscale step).
    tailscale_multinode(ctx);
    // AFTER the multinode capture: the OAuth client / API key it collects
    // is what lets the tag assertion below run hands-off.
    ensure_controller_tag(ctx);

    ctx.success("PKI + enrollment complete.");
}

/// Grafana's single sign-on and its door. Until this, no
/// step wrote `GRAFANA_ROOT_URL`, so the gateway's `NOO_GRAFANA_URL` was
/// empty and "Open Grafana" answered 503 on every fresh install. Derived
/// from the bind mode chosen above and this box's tailnet identity — the
/// same derivation `noo upgrade --stack` uses to repair an install that
/// predates it. After `ensure_pki`, whose loop gave Grafana's leaf the
/// tailnet name this URL uses.
fn grafana_door(ctx: &mut Ctx) {
    grafana_door_with(ctx, &crate::tailnet_serve::ensure_grafana_fronted, &crate::tailnet_serve::ensure_grafana_login)
}

/// [`grafana_door`] with the serve write passed in, so a test can see the
/// call without touching the machine's tailscale config.
fn grafana_door_with(
    ctx: &mut Ctx,
    front: &dyn Fn(u32, bool) -> Result<crate::tailnet_serve::Fronting, crate::tailnet_serve::FrontError>,
    login: &dyn Fn(u32, bool) -> Result<crate::tailnet_serve::Fronting, String>,
) {
    use crate::commands::grafana_door as gd;
    let mode = ctx.read_env("NOO_BIND_MODE");
    let door = gd::door_for(&mode, &ctx.state.ts_dnsname, &ctx.state.ts_ip, gd::BASE_PORT + ctx.state.port_offset);
    if ctx.dry_run {
        let settled = door.settled(true);
        ctx.dry(&format!(
            "Grafana single sign-on: {}={} unless set, published on {}",
            gd::ROOT_URL_KEY, settled.root_url, settled.bind_addr
        ));
        if let Some(port) = door.serve_port {
            ctx.dry(&format!(
                "{} (only Grafana's port; Grafana stays on {} unless it is confirmed)",
                crate::tailnet_serve::grafana_manual_line(port),
                door.bind_addr
            ));
        }
        return;
    }
    // The tailnet door: `tailscale serve` answers Grafana's port on the
    // tailnet name with the tailnet's certificate; Grafana moves to loopback
    // only once that is confirmed (grafana_door.rs, fail-safe order). Same
    // reconcile `noo upgrade --stack` runs.
    let non_interactive = ctx.non_interactive;
    let instance = gd::canonical_instance(&ctx.read_env("NOO_INSTANCE"));
    let report = gd::reconcile_door(
        &ctx.env_path,
        &door,
        &instance,
        &|port| front(port, non_interactive),
        &|port| login(port, non_interactive),
    );
    match &report.front {
        Some((_, Ok(crate::tailnet_serve::Fronting::Written))) => {
            ctx.success(&format!("tailscale serve configured: {} → Grafana", report.door.root_url))
        }
        Some((_, Ok(crate::tailnet_serve::Fronting::Already))) => {
            ctx.info(&format!("tailscale serve already fronts Grafana at {}", report.door.root_url))
        }
        _ => {}
    }
    if let Some(w) = report.warning() {
        ctx.warn(&w);
    }
    if let Some(w) = report.login_warning() {
        ctx.warn(&w);
    }
    match report.said {
        Ok(said) if said.is_empty() => {
            ctx.info(&format!("Grafana single sign-on: {} already set (kept)", gd::ROOT_URL_KEY));
        }
        Ok(said) => {
            for s in said {
                ctx.success(&s);
            }
        }
        Err(e) => ctx.warn(&format!(
            "Grafana single sign-on is OFF: {e}. Open Grafana answers 503 until {} is in .env; then: noo stack restart --force",
            gd::ROOT_URL_KEY
        )),
    }
}

/// Why the store could not be armed, and what fixes it. Every refusal is a
/// hard failure: the wizard stops before any secret is minted and exits 1.
fn refuse_store(ctx: &mut Ctx, why: &str, fix: &str) -> bool {
    ctx.error(&format!("{why} — onboarding stops here: a secret is never written to plaintext .env"));
    ctx.raw(&format!("    fix: {fix}"));
    ctx.state.hard_failures.push(format!("secrets: {why}. Fix: {fix}"));
    false
}

/// Make the encrypted store (`secrets/env.sops`) this install's live secrets
/// backend, BEFORE anything is minted. There is no plaintext alternative:
/// `--secrets-backend env` is refused at parse time, and a missing or failing
/// init script is a hard failure (returns false) — it used to warn "leaving
/// plaintext .env" and let the wizard finish green.
///
/// * No store yet: `scripts/noo-secrets-sops-init.sh` installs sops/age,
///   makes the age key and encrypts `.env` into the store. On a fresh install
///   `.env` holds config only at this point; its config keys are moved back
///   out of the store (secrets only in sops).
/// * Then, store new or old: every secret-class value still in `.env` is
///   carried into the store and its `.env` slot blanked. Which copy wins
///   follows what the stack was READING: on an install that was not on sops,
///   `.env` was live, so its values overwrite the store's; on a sops install
///   the store was live, so only keys it lacks are carried. A carry that
///   fails changes nothing in `.env`.
fn arm_secret_store(ctx: &mut Ctx) -> bool {
    let was_sops = ctx.sops_active();
    let store = ctx.secrets_dir.join("env.sops");
    let script = ctx.repo_root.join("scripts/noo-secrets-sops-init.sh");
    if !store.exists() {
        if !script.exists() {
            return refuse_store(
                ctx,
                &format!(
                    "the SOPS init script is missing ({}), so there is no encrypted store to put secrets in",
                    script.display()
                ),
                "restore the deploy files (standalone: noo upgrade --stack re-materialises them; checkout: git checkout it), then re-run: noo onboard --reconfigure --only secrets",
            );
        }
        if ctx.dry_run {
            ctx.dry("run scripts/noo-secrets-sops-init.sh + set NOO_SECRETS_BACKEND=sops (before any secret is minted)");
            return true;
        }
        // The script encrypts the current .env and refuses without one; a
        // `--only secrets` run on a bare home has none yet.
        if !ctx.env_path.exists() {
            let _ = std::fs::write(&ctx.env_path, "");
            let _ = std::fs::set_permissions(&ctx.env_path, std::fs::Permissions::from_mode(0o600));
        }
        ctx.progress("Creating the encrypted secret store (SOPS+age)...");
        let ok = Command::new("bash")
            .arg(&script)
            .current_dir(&ctx.repo_root)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok || !store.exists() {
            return refuse_store(
                ctx,
                "the SOPS init script failed (see its output above), so there is no encrypted store",
                "fix what it reported (it installs sops + age to ~/.local/bin and needs network for that), then re-run: noo onboard --reconfigure --only secrets",
            );
        }
    } else if ctx.dry_run {
        ctx.dry("set NOO_SECRETS_BACKEND=sops; carry any plaintext secret in .env into secrets/env.sops and blank it");
        return true;
    }
    // Readable by THIS process, or nothing below can write to it.
    if let Err(e) = crate::commands::secrets::SecretStore::load_sops(&store) {
        return refuse_store(
            ctx,
            &format!("secrets/env.sops exists but cannot be decrypted here ({e})"),
            &format!(
                "restore the matching age key to {}, then re-run: noo onboard --reconfigure --only secrets",
                crate::age_key::default_path().display()
            ),
        );
    }
    // The encryption consumed the current .env this very second — the
    // "re-encrypt after this change" trap warning would be a false alarm
    // (finding #69). Later .env edits still warn.
    ctx.suppress_sops_warning();
    ctx.update_env("NOO_SECRETS_BACKEND", "sops");
    ctx.forget_store_cache();
    // The whole-file encrypt also put every CONFIG key in the store, where
    // it shadows .env at every launch. Secrets only — config goes back.
    match crate::commands::secrets::store_move_config_to_env(&ctx.env_path) {
        Ok(moved) if !moved.is_empty() => ctx.info(&format!(
            "{} config key(s) moved out of the store back to .env (secrets only in sops)", moved.len())),
        Ok(_) => {}
        Err(e) => ctx.warn(&format!("could not thin the store to secrets only ({e}) — run: noo security secrets tidy")),
    }
    let carried = match carry_plaintext_into_store(ctx, !was_sops) {
        Ok(n) => n,
        Err(e) => {
            return refuse_store(
                ctx,
                &format!("could not move the plaintext secrets in .env into secrets/env.sops ({e}); .env was left as it was"),
                "noo security secrets audit   # then re-run: noo onboard --reconfigure --only secrets",
            );
        }
    };
    ctx.forget_store_cache();
    ctx.success(&format!(
        "Secrets encrypted at rest (SOPS+age){}. BACK UP your age key: {} — it is the root of trust.",
        if carried > 0 { format!("; {carried} plaintext secret(s) moved out of .env") } else { String::new() },
        crate::age_key::path().display()
    ));
    true
}

/// The keys [`carry_plaintext_into_store`] writes to the store: every
/// secret-class `.env` value when `.env` was the live copy, else only those
/// the store lacks. Pure, so the precedence is tested without sops.
pub(crate) fn carry_plan(
    plaintext: &[(String, String)],
    env_was_live: bool,
    stored: &dyn Fn(&str) -> bool,
) -> Vec<(String, String)> {
    plaintext
        .iter()
        .filter(|(k, _)| env_was_live || !stored(k))
        .cloned()
        .collect()
}

/// Move every secret-class value in `.env` into the store (one atomic,
/// round-trip-verified write), THEN blank each `.env` slot. Returns how many
/// were blanked. On a store error nothing in `.env` is touched.
fn carry_plaintext_into_store(ctx: &mut Ctx, env_was_live: bool) -> Result<usize, String> {
    let pairs = crate::onboard::env::read_env_pairs(&ctx.env_path);
    let keys = crate::commands::plaintext_env::plaintext_secret_keys(&pairs);
    if keys.is_empty() {
        return Ok(0);
    }
    let values: Vec<(String, String)> = keys
        .iter()
        .map(|k| (k.clone(), crate::onboard::env::read_env_key(&ctx.env_path, k)))
        .collect();
    let store = crate::commands::secrets::SecretStore::load_sops(&ctx.secrets_dir.join("env.sops"))?;
    let plan = carry_plan(&values, env_was_live, &|k| {
        store.state(k) == crate::commands::secrets::State::Set
    });
    if !plan.is_empty() {
        crate::commands::secrets::store_upsert(&plan)?;
    }
    let mut n = 0;
    for key in &keys {
        match crate::onboard::env::update_env_key(&ctx.env_path, key, "") {
            Ok(()) => n += 1,
            Err(e) => ctx.warn(&format!("could not blank {key} in .env: {e}")),
        }
    }
    Ok(n)
}

/// The services onboard starts and recreates on a dev (source-build)
/// install: what the `controller` profile projects, minus the host-owned
/// containerised agent and, on a host without the NVIDIA runtime, the GPU
/// exporter (`sh::recreate_set`). `None` after telling the operator why —
/// a wizard that cannot read its own compose projection has nothing honest
/// to start. A dry run cannot read it either and prints the profile name.
fn controller_services(ctx: &mut Ctx) -> Option<Vec<String>> {
    if ctx.dry_run {
        ctx.dry("docker compose --profile controller config --services   (the set onboard starts)");
        return Some(vec!["postgres".into(), "redis".into(), "nats".into(), "trellion".into(), "gateway".into()]);
    }
    match sh::profile_services(ctx, "controller") {
        Some(projected) => Some(sh::recreate_set(&projected, sh::nvidia_runtime_present(ctx))),
        None => {
            ctx.error("could not read the compose projection (docker compose --profile controller config --services) — nothing to start");
            ctx.state.hard_failures.push("services: the compose projection could not be read (see the compose output above)".into());
            None
        }
    }
}

/// Externally-reachable services need the controller LAN IP in their SAN.
pub(crate) const SVC_LIST: &[&str] = &[
    "redis", "nats", "postgres", "vllm", "llamacpp", "ollama", "tei", "reranker", "loki",
    // The standalone profile's embedder, presented by its stunnel sidecar
    // (docker/stunnel-ollama-embed.conf). Its own leaf, not `ollama`'s:
    // `noo upgrade --stack` issues a MISSING leaf on its own
    // (upgrade.rs reconcile_service_certs) while a SAN added to an
    // existing one needs `noo onboard --only security` — a new name is
    // the roll-safe shape. Issued on every install shape; a leaf is cheap.
    "ollama-embed",
    // The optional CPU embedder's door (compose profile `embed-cpu`): its
    // own leaf for the same roll-safe reason — a new name that
    // `noo upgrade --stack` issues on its own.
    "ollama-embed-cpu",
    "node-exporter", "nvidia-exporter", "grafana", "prometheus", "alertmanager",
    // The request-trace store (i359): its OTLP and query doors require a
    // cluster client cert; the gateway is the only caller.
    "tempo",
    "model-cache",
    // The trellion add-ons' own identities: the client
    // certificate noo-trellion and noo-trellion-intel present to Postgres,
    // Redis, NATS and the gateway. Both used to mount the controller's
    // gateway leaf. Issued whether or not the add-on is on, like `evolve`.
    "trellion", "trellion-intel",
    // noo-worker's own identity: what it
    // and worker-extra present to Postgres, Redis, NATS, the gateway and
    // the backend doors. It used to mount the controller's gateway leaf.
    "worker",
    // The evolve add-on's own identity toward Postgres, which requires a
    // cluster-CA client certificate from every TCP client (2026-09-28).
    // Issued whether or not the add-on is on: a leaf is cheap, and an
    // add-on switched on later must not need the wizard re-run to reach
    // the database. NOT the gateway leaf — see evolve's bundled overlay.
    "evolve",
    // A warm standby's replication identity: the
    // client certificate `scripts/bootstrap-standby.sh join` presents to
    // the primary, whose pg_hba requires one for `replication` too. Only
    // ever a CLIENT leaf, so its SANs do not matter; no service here
    // mounts it. Issued everywhere for the same reason `evolve` is: the
    // day a standby is wanted, its leaf is already on the primary.
    "postgres-standby",
    // The sandbox executor's door (mTLS doors phase 1, i77): uvicorn serves
    // this leaf with `--ssl-cert-reqs 2`, so the gateway, the worker and
    // trellion reach it only with a cluster-CA client certificate. A new
    // name, so `noo upgrade --stack` issues it on its own before the roll
    // (upgrade.rs reconcile_service_certs). sandbox-extra replicas answer
    // to the `sandbox` alias and mount this same leaf.
    "sandbox",
    // The voice add-on's doors (mTLS doors phase 2, i77): uvicorn in
    // noo-whisper / noo-piper serves each leaf with `--ssl-cert-reqs 2`,
    // and the gateway dials them with its own. Issued whether or not
    // `addons.voice` is on, like `evolve`: a leaf is cheap, the add-on
    // switched on later must not need the wizard re-run, and a missing
    // bind source would be created root-owned by Docker on first start.
    "whisper", "piper",
];
/// Dialled from OTHER hosts by the controller's reachable names, so the leaf
/// carries `noo-controller`, the LAN IP and the tailnet name. `model-cache`
/// joined in an earlier release: a node preseeds weights over mTLS from
/// `https://<controller>:8443`, by whichever of those names provision wrote.
pub(crate) const EXTERNALLY_REACHABLE: &[&str] = &["nats", "redis", "postgres", "model-cache"];

pub(crate) fn svc_extra_hostnames(svc: &str) -> Vec<String> {
    let v: &[&str] = match svc {
        // vllm-secondary shares the primary's leaf (same mount, same
        // entrypoint paths), so the leaf must claim its name too or every
        // caller fails hostname verification against the secondary.
        "vllm" => &["noo-vllm", "noo-vllm-secondary"],
        // llama-server has no TLS listener; the leaf is presented by the
        // stunnel-llamacpp sidecar, dialled by container name (the
        // controller's own agent resolves container names) or compose alias.
        "llamacpp" => &["noo-llamacpp", "stunnel-llamacpp", "noo-stunnel-llamacpp"],
        "ollama" => &["noo-ollama", "stunnel-ollama"],
        // Ollama has no TLS listener; the standalone embedder's leaf is
        // presented by the stunnel-ollama-embed sidecar, dialled by
        // container name (STANDALONE_OLLAMA_EMBED_URL) or compose alias.
        "ollama-embed" => &["noo-ollama-embed", "stunnel-ollama-embed", "noo-stunnel-ollama-embed"],
        "ollama-embed-cpu" => &["noo-ollama-embed-cpu", "stunnel-ollama-embed-cpu", "noo-stunnel-ollama-embed-cpu"],
        "tei" => &["noo-tei", "stunnel-tei"],
        "reranker" => &["noo-reranker", "stunnel-reranker"],
        "redis" => &["noo-redis"],
        "nats" => &["noo-nats"],
        "postgres" => &["noo-postgres"],
        "trellion" => &["noo-trellion"],
        "trellion-intel" => &["noo-trellion-intel"],
        "worker" => &["noo-worker"],
        "grafana" => &["noo-grafana"],
        "prometheus" => &["noo-prometheus"],
        // Serves TLS to Prometheus with a required client cert
        // 1234 B); without this leaf the container does not start.
        "alertmanager" => &["noo-alertmanager"],
        // Prometheus is on this list so it scrapes with its
        // OWN leaf. Before it, it mounted gateway.{crt,key} — the
        // controller's identity, which a node agent reads as "this caller
        // may command me". Dropping the name here does not make the
        // monitoring stack fail loudly; it makes the next operator put the
        // gateway key back. (promtail had the same entry until fleet
        // logging phase 4 retired it; the node-agent ships instead.)
        "loki" => &["noo-loki"],
        "tempo" => &["noo-tempo"],
        "node-exporter" => &["noo-node-exporter"],
        "nvidia-exporter" => &["noo-nvidia-exporter"],
        // The weight store's mTLS listener. The
        // compose alias for a containerised agent on the controller itself;
        // remote nodes get the EXTERNALLY_REACHABLE names on top.
        "model-cache" => &["noo-model-cache"],
        "evolve" => &["noo-evolve"],
        // Callers dial the `sandbox` alias (the extras carry it too); the
        // container and replica service names ride along so a probe by
        // either still verifies.
        "sandbox" => &["noo-sandbox", "sandbox-extra"],
        // The gateway's default voice URLs dial the container names
        // (https://noo-whisper:8000, https://noo-piper:8000); the compose
        // service name rides in as the leaf's CN SAN.
        "whisper" => &["noo-whisper"],
        "piper" => &["noo-piper"],
        _ => &[],
    };
    v.iter().map(|s| s.to_string()).collect()
}

/// The SAN set onboarding gives one service cert: `svc_extra_hostnames`
/// plus, for `EXTERNALLY_REACHABLE` services, the controller's LAN IP and
/// its own aliases (`noo-controller`, hostname, lowercased hostname) and
/// the tailnet name. Shared with `upgrade_stack`'s cert-reconcile pass
/// (newcomer-upgrade rehearsal, 2026-09-29) so a release that adds a new
/// mounted service cert gets the SAME coverage whether the box ran
/// onboarding fresh or arrived here by upgrade — one derivation, not two
/// that can drift apart.
pub(crate) fn service_cert_sans(
    svc: &str,
    hostname: &str,
    node_ip: &str,
    ts_dnsname: &str,
) -> (Vec<String>, Vec<String>) {
    let mut extra = svc_extra_hostnames(svc);
    let mut extra_ips: Vec<String> = Vec::new();
    // Grafana's door on a tailnet controller is https://<tailnet-name>:<port>
    // The browser verifies that
    // name against this leaf.
    if svc == "grafana" && !ts_dnsname.is_empty() {
        extra.push(ts_dnsname.to_string());
    }
    if EXTERNALLY_REACHABLE.contains(&svc) {
        if !node_ip.is_empty() {
            extra_ips.push(node_ip.to_string());
        }
        for h in [
            "noo-controller".to_string(),
            hostname.to_string(),
            hostname.to_lowercase(),
        ] {
            if !extra.contains(&h) {
                extra.push(h);
            }
        }
        // The tailnet name is how HOST-plane consumers (the native
        // node agent, remote nodes) reach this controller's bus —
        // it belongs in the cert exactly like the gateway's.
        if !ts_dnsname.is_empty() && !extra.contains(&ts_dnsname.to_string()) {
            extra.push(ts_dnsname.to_string());
        }
    }
    (extra, extra_ips)
}

/// This box's `(hostname, LAN IP, tailnet DNS name)` as the cert derivation
/// wants them: the same three inputs onboarding's `ensure_pki` feeds
/// [`service_cert_sans`], for the paths that run without an onboarding
/// context (`upgrade --stack`, `pki issue-service`, `cluster verify`). The
/// tailnet name is empty when the box has none.
pub(crate) fn local_cert_identity() -> (String, String, String) {
    let hostname = Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "mesh-gateway".to_string());
    let ts = tailscale_identity().map(|(dns, _)| dns).unwrap_or_default();
    (hostname, util::detect_ip(), ts)
}

/// What [`ensure_service_cert_names`] found and did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NamesOutcome {
    /// No certificate here yet (the missing-cert pass issues it).
    NoLeaf,
    /// The leaf already carries every derived name.
    Covered,
    /// Re-issued. `missing` is what it lacked; `unreadable` is set when the
    /// old file could not be parsed, in which case `missing` is empty.
    Reissued { missing: Vec<String>, unreadable: Option<String> },
}

/// Compare an EXISTING service leaf's SANs with [`service_cert_sans`] and
/// re-issue it when names are missing
/// special case, generalised). An unreadable or unparseable leaf is ours to
/// manage, so it is re-issued and the outcome says why. A failed issue is
/// `Err` and leaves the old files as they were: every failure point of
/// `issue_service_cert` (CA load, keygen, signing) is before its first
/// write, and the certificate is written before the key. The caller
/// recreates the consumer (`upgrade --stack`'s launcher force-recreates).
pub(crate) fn ensure_service_cert_names(
    ca: &ClusterCa,
    svc: &str,
    hostname: &str,
    node_ip: &str,
    ts_dnsname: &str,
) -> Result<NamesOutcome, String> {
    let crt = ca.dir.join("services").join(svc).join("service.crt");
    if !crt.is_file() {
        return Ok(NamesOutcome::NoLeaf);
    }
    let (extra, extra_ips) = service_cert_sans(svc, hostname, node_ip, ts_dnsname);
    let mut want: Vec<String> = vec![svc.to_string(), "localhost".into()];
    want.extend(extra.iter().cloned());
    let (missing, unreadable) = match ClusterCa::cert_names(&crt) {
        Ok(have) => {
            let missing = crate::pki::missing_names(&have, &want, &extra_ips);
            if missing.is_empty() {
                return Ok(NamesOutcome::Covered);
            }
            (missing, None)
        }
        Err(e) => (Vec::new(), Some(e)),
    };
    ca.issue_service_cert(svc, &extra, &extra_ips, DEFAULT_DAYS)?;
    Ok(NamesOutcome::Reissued { missing, unreadable })
}

fn ensure_pki(ctx: &mut Ctx) {
    let ca = ClusterCa::new(ctx.pki_dir.clone());
    let hostname = Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "mesh-gateway".to_string());
    let node_ip = util::detect_ip();

    if ctx.dry_run {
        if ca.ca_exists() {
            ctx.info("Cluster CA already exists");
        } else {
            ctx.dry("generate cluster CA (Mesh Cluster CA)");
        }
        ctx.dry("issue gateway + service + node certs, set PKI/TLS env keys");
    } else {
        if !ca.ca_exists() {
            match ca.generate_ca("Mesh Cluster CA", 3650) {
                Ok(_) => ctx.success("Cluster CA certificate generated"),
                Err(e) => {
                    ctx.error(&format!("CA generation failed: {e}"));
                    return;
                }
            }
            // A NEW CA orphans every fleet node keyed under the old one:
            // agents crash-retry with "certificate signed by unknown
            // authority" and just show OFFLINE (2026-08-06). If this host
            // already knows registered nodes, say so NOW, not after the
            // fleet has silently fallen off.
            // Counted from `ansible/inventory/hosts` until 2026-09-04 — a
            // file in the tree deleted in 3695e129 — so the count was always
            // ZERO and this warning, the one that exists to stop you
            // stranding a live fleet behind a new CA, had stopped firing
            // entirely. The registry knows what is enrolled.
            let remote = crate::commands::security_local::fleet_nodes_from_registry(ctx.g)
                .into_iter()
                .filter(|(name, _, _)| !name.eq_ignore_ascii_case(&hostname))
                .count();
            if remote > 0 {
                ctx.warn(&format!(
                    "This is a NEW cluster CA and {remote} registered node(s) still hold certs \
                     from the old one — they will stay OFFLINE until re-keyed. \
                     After setup completes, run: noo security pki push-nodes"
                ));
            }
        } else {
            ctx.info("Cluster CA already exists");
        }

        // #44: an --only run skips the tailscale STEP, but cert issuance
        // still needs the tailnet identity — without this hydration the
        // always-reissued gateway cert lost its ts.net SANs and the next
        // recreate would have broken the dashboard (live 2026-08-25).
        // Read-only: no prompts, no writes, just fill the state the
        // skipped step would have filled.
        if ctx.state.ts_dnsname.is_empty() {
            if let Ok((dns, ip)) = tailscale_identity() {
                ctx.state.ts_dnsname = dns;
                ctx.state.ts_ip = ip;
            }
        }
        // Gateway cert (always re-issued, like Python). Tailnet identity
        // from the Tailscale step goes into the SANs — without it,
        // `tailscale serve` cannot verify the backend and the tailnet
        // dashboard 502s. Its absence must be LOUD, never a silent success.
        let mut extra_sans: Vec<String> = Vec::new();
        let mut extra_ips: Vec<String> = Vec::new();
        if !ctx.state.ts_dnsname.is_empty() {
            extra_sans.push(ctx.state.ts_dnsname.clone());
            extra_ips.push(ctx.state.ts_ip.clone());
        }
        match ca.issue_gateway_cert(&hostname, &node_ip, DEFAULT_DAYS, &extra_sans, &extra_ips) {
            Ok(_) => {
                if extra_sans.is_empty() {
                    ctx.warn(
                        "Gateway TLS certificate generated WITHOUT tailnet SANs — \
                         tailnet HTTPS (tailscale serve) will fail against this cert. \
                         Join the tailnet and re-run 'noo onboard --reconfigure' to fix.",
                    );
                } else {
                    ctx.success(&format!(
                        "Gateway TLS certificate generated (SANs include {} + {})",
                        ctx.state.ts_dnsname, ctx.state.ts_ip
                    ));
                }
            }
            Err(e) => ctx.warn(&format!("gateway cert: {e}")),
        }

        // The controller records where its own gateway is, at the moment it
        // decides what name the certificate will carry.
        //
        // `/etc/noo/controller-url` is the CLI's third resolution rung
        // (override -> $CONTROLLER_URL -> this file -> localhost). It has
        // only ever been written by `prep-host.sh`, which runs on an
        // ENROLLED NODE — and a controller is never enrolled, it is the
        // thing nodes enroll into. So the one box guaranteed to be running a
        // gateway was the one box with no record of where that gateway is,
        // and every `noo` command there fell through to
        // `https://localhost:8080`.
        //
        // Which the certificate issued three lines above does not name. The
        // TLS handshake then fails, and it surfaces as "no response from the
        // identity endpoint" rather than as a certificate error — so it
        // reads as a gateway that is down. It cost an operator a debugging
        // session on 2026-09-06 that looked like a lost password: `noo auth
        // login` against an unreachable target failed quietly, and the
        // stored credential said "issued by <tailnet>, not the current
        // target" about the machine they were standing on.
        //
        // Writing it HERE and not in a later step is deliberate: this is
        // where the SAN set is chosen, so the URL the CLI resolves and the
        // name the certificate carries come from one value and cannot drift.
        if !ctx.state.ts_dnsname.is_empty() {
            let url = format!("https://{}:{}", ctx.state.ts_dnsname, gateway_port());
            match write_controller_url(&url, ctx_sudo_may_prompt(ctx)) {
                Ok(()) => ctx.success(&format!("Controller URL recorded: {url}")),
                // Not fatal. The stack comes up either way; the cost is that
                // `noo` on this box needs $CONTROLLER_URL until it is fixed,
                // so say exactly that rather than failing the wizard.
                Err(e) => {
                    ctx.warn(&format!("could not write {ENROLLED_CONTROLLER_URL}: {e}"));
                    ctx.raw("    `noo` on this box will default to localhost, which this certificate does not name.");
                    ctx.raw(&format!("    Until fixed: export CONTROLLER_URL={url}"));
                    sudo_refused(ctx, "controller URL", &format!("echo {url} | sudo tee {ENROLLED_CONTROLLER_URL}"));
                }
            }
        }

        // Service certs — issued when missing, RE-issued when the required
        // SAN set outgrew the existing cert. Skip-if-exists left certs
        // without the tailnet DNS name in place, and every host-plane dial
        // (self-agent → nats via ts.net) failed hostname verification with
        // both sides logging only "bad certificate" (first-contact finding
        // #33). Coverage is the criterion, not existence.
        for svc in SVC_LIST {
            let crt = ctx.pki_dir.join("services").join(svc).join("service.crt");
            let (extra, extra_ips) =
                service_cert_sans(svc, &hostname, &node_ip, &ctx.state.ts_dnsname);
            if crt.exists() {
                let mut req_dns: Vec<String> = vec![svc.to_string(), "localhost".into()];
                req_dns.extend(extra.iter().cloned());
                if crate::pki::ClusterCa::cert_covers_sans(&crt, &req_dns, &extra_ips) {
                    ctx.info(&format!("{svc} service certificate already exists"));
                    continue;
                }
                ctx.info(&format!("{svc} certificate is missing required SANs — re-issuing"));
            }
            match ca.issue_service_cert(svc, &extra, &extra_ips, DEFAULT_DAYS) {
                Ok(_) => ctx.success(&format!("{svc} service certificate generated")),
                Err(e) => ctx.warn(&format!("{svc} cert: {e}")),
            }
        }

        // Postgres role leaves (i132): one client identity per role and
        // container, CN = the role, so pg_hba's `clientcert=verify-full` can
        // say which role a certificate may log in as. Not part of SVC_LIST:
        // a role leaf is named for its ROLE and has no SANs to keep covered.
        // Issued when missing (or when a hand-made one has the wrong CN or
        // no key); a failure is a warning here, and `noo upgrade --stack`
        // refuses to roll without them.
        for (leaf, res) in ca.ensure_pg_leaves(DEFAULT_DAYS) {
            match res {
                Ok(true) => ctx.success(&format!("Postgres client certificate for role {} ({}) generated", leaf.role, leaf.owner)),
                Ok(false) => ctx.info(&format!("Postgres client certificate for role {} ({}) already exists", leaf.role, leaf.owner)),
                Err(e) => ctx.warn(&format!(
                    "Postgres client certificate for role {} ({}): {e} — then: noo security pki fix-modes, and re-run: noo onboard --only security",
                    leaf.role, leaf.owner
                )),
            }
        }

        // Node cert — same coverage rule as service certs (finding #33):
        // the gateway dials the agent back by its registered tailnet name,
        // so the node cert must carry it or the callback handshake fails.
        // Finding #79: the tailnet IP too, not only the name — the agent
        // registers agent_url with DetectHostIP (its route to the
        // controller = the TAILSCALE address on a tailnet controller), and
        // gpu_health/node_dispatch_health dial that address every 300s.
        // #33 pushed ts_ip into the GATEWAY cert; the node cert only got
        // the DNS name, so every probe died in "bad certificate" and both
        // GPU watchdogs sat disarmed. Listing the IP in node_req_ips makes
        // cert_covers_sans force a re-issue on existing installs.
        let node_crt = ctx.pki_dir.join("nodes").join(&hostname).join("node.crt");
        let mut node_sans = vec!["node-agent".to_string()];
        if !ctx.state.ts_dnsname.is_empty() {
            node_sans.push(ctx.state.ts_dnsname.clone());
        }
        let mut node_extra_ips: Vec<String> = Vec::new();
        if !ctx.state.ts_ip.is_empty() {
            node_extra_ips.push(ctx.state.ts_ip.clone());
        }
        // i11a: this IS the controller's own node, so its cert carries the
        // controller names too, and a cert that lacks them is re-issued.
        let node_role = {
            let mut src = crate::pki::ControllerNames::declared_sources();
            src.push(ctx.state.ts_dnsname.clone());
            src.push(ctx.state.ts_ip.clone());
            crate::pki::NodeRole::Controller(crate::pki::ControllerNames::from_sources(&src))
        };
        let node_req: Vec<String> = {
            let mut v = vec![hostname.clone()];
            v.extend(node_sans.iter().cloned());
            v.extend(node_role.required_dns().iter().cloned());
            v
        };
        let mut node_req_ips: Vec<String> =
            if node_ip.is_empty() { vec![] } else { vec![node_ip.clone()] };
        node_req_ips.extend(node_extra_ips.iter().cloned());
        if node_crt.exists()
            && crate::pki::ClusterCa::cert_covers_sans(&node_crt, &node_req, &node_req_ips)
        {
            ctx.info(&format!("Node certificate for {hostname} already exists"));
        } else {
            if node_crt.exists() {
                ctx.info(&format!("node certificate for {hostname} is missing required SANs — re-issuing"));
            }
            match ca.issue_node_cert(&hostname, &node_ip, DEFAULT_DAYS, &node_sans, &node_extra_ips, &node_role) {
                Ok(_) => ctx.success(&format!("Node certificate generated for {hostname}")),
                Err(e) => ctx.warn(&format!("node cert: {e}")),
            }
        }

        // Grafana SSO key pair: the gateway signs Grafana
        // session tokens with `sso/grafana.key`; Grafana verifies them with
        // `sso/grafana.pub`, the ONE sso file it mounts. Not a TLS leaf, so
        // it lives outside services/ and `rotate-all` never touches it —
        // rotating it logs every open Grafana tab out. Idempotent: an
        // install from before this key acquires one on the next onboard.
        match ca.ensure_grafana_sso_key() {
            Ok(true) => ctx.success("Grafana SSO key pair generated (pki/sso/)"),
            Ok(false) => ctx.info("Grafana SSO key pair already exists"),
            Err(e) => ctx.warn(&format!("grafana sso key: {e}")),
        }
        if let Err(e) = ca.grafana_sso_key_grant_gateway_read() {
            // Not fatal: the gateway's "Open Grafana" answers 503 naming this
            // same command until it is done.
            ctx.warn(&format!("grafana sso key: {e}"));
        }

        // The gateway's certificate-only view: the gateway
        // bind-mounts `public/nodes`, `public/services` and `sso/` instead
        // of the PKI root, so they must exist — as the operator's, before
        // any start, or the launcher refuses the missing bind source — and
        // `public/` must carry every certificate the steps above issued.
        let view = ca.sync_public_view();
        if view.errors.is_empty() {
            ctx.info(&format!("Gateway certificate view: {} certificate(s) under pki/public/", view.total));
        } else {
            for e in &view.errors {
                ctx.warn(&format!("gateway certificate view (pki/public/): {e} — then: noo security pki fix-modes"));
            }
        }

        // Private-key modes for an install that predates them (leaf keys
        // were 0644 until 2026-09-28: every container uid, the gateway
        // through its whole-tree mount included, could read every node's
        // and service's key). Idempotent — `noo security pki fix-modes` is
        // the same pass on demand; a key this process cannot hand to its
        // container uid is left as it was and the sudo line printed, so
        // nothing stops starting.
        let (fixes, dirs) = ca.fix_key_modes();
        let changed: Vec<&crate::pki::KeyFix> = fixes.iter().filter(|f| f.changed()).collect();
        if changed.is_empty() && dirs.is_empty() {
            ctx.info(&format!("Private-key modes already set ({} keys)", fixes.len()));
        } else {
            ctx.success(&format!(
                "Private-key modes set: {} key(s) tightened{}",
                changed.len(),
                if dirs.is_empty() { String::new() } else { format!(", {} dir(s) to 0755", dirs.len()) }
            ));
            for f in &changed {
                ctx.raw(&format!("    {}: {:04o} → {:04o} ({})", f.rel, f.before, f.after, f.reader.describe()));
            }
        }
        // i266: a key this process could not hand to its container uid is
        // 0644 (fail open) with the sudo line printed. A fresh `--ci` install
        // on a box with no setfacl left 32 such keys readable by every local
        // account, reported success, and only `cluster verify` said so.
        // With sudo usable the grant is made here and verified; without it
        // the run says so plainly and does not complete.
        let outstanding: Vec<crate::pki::KeyFix> = fixes.iter().filter(|f| f.needs.is_some()).cloned().collect();
        let interactive = !ctx.non_interactive && ctx.ui.inherit_stdio() && super::prompt::stdin_is_tty();
        let sudo_usable = !outstanding.is_empty() && (interactive || passwordless_sudo());
        match crate::pki::key_grant_plan(outstanding.len(), sudo_usable) {
            crate::pki::KeyGrantPlan::Nothing => {}
            crate::pki::KeyGrantPlan::Sudo => {
                ctx.progress(&format!("Handing {} private key(s) to their container uid through sudo...", outstanding.len()));
                let mut done = 0usize;
                for f in &outstanding {
                    let key = ctx.pki_dir.join(&f.rel);
                    match f.reader {
                        crate::pki::KeyReader::ContainerUid(uid) if f.needs.as_deref().is_some_and(|n| n.starts_with("sudo chgrp")) => {
                            match crate::pki::grant_read_to_uid_via_sudo(&key, uid, !interactive) {
                                Ok(()) => done += 1,
                                Err(cmd) => ctx.warn(&format!("{} is not readable by its container uid ({}); run: {cmd}", f.rel, f.reader.describe())),
                            }
                        }
                        _ => ctx.warn(&format!("{} ({}); run: {}", f.rel, f.reader.describe(), f.needs.as_deref().unwrap_or_default())),
                    }
                }
                if done > 0 {
                    ctx.success(&format!("{done} private key(s) handed to their container uid (0640, group = uid) through sudo"));
                }
                // Verified, not assumed: the audit the scan and `cluster verify` use.
                let still: Vec<String> = ca
                    .audit_key_modes()
                    .into_iter()
                    .filter(|i| outstanding.iter().any(|f| f.rel == i.rel) && matches!(i.kind, crate::pki::KeyIssueKind::Exposed | crate::pki::KeyIssueKind::Unreadable))
                    .map(|i| i.rel)
                    .collect();
                if !still.is_empty() {
                    let text = crate::pki::exposed_keys_failure(still.len());
                    ctx.error(&text);
                    ctx.state.hard_failures.push(text);
                }
            }
            crate::pki::KeyGrantPlan::Loud => {
                for f in &outstanding {
                    ctx.warn(&format!("{} is not readable by its container uid ({}); run: {}", f.rel, f.reader.describe(), f.needs.as_deref().unwrap_or_default()));
                }
                let text = crate::pki::exposed_keys_failure(outstanding.len());
                ctx.error(&text);
                ctx.state.hard_failures.push(text);
            }
        }
    }

    // TLS env keys (parity with _ensure_pki)
    let pki = ctx.pki_dir.to_string_lossy().into_owned();
    for (k, v) in [
        ("NOO_PKI_DIR", pki.clone()),
        ("NOO_TLS_CA", format!("{pki}/ca.crt")),
        ("NOO_MTLS_NODES", "true".into()),
        // Enforce certificate identity on a FRESH install. Every node cert
        // here is issued by this wizard, moments ago, naming the node it
        // belongs to — so there is no drifted cert to lock out, which is
        // the only reason this is not simply the default everywhere. An
        // UPGRADED install leaves it empty and opts in after checking its
        // logs for mismatch warnings (the gateway logs both sides without
        // refusing until this is on).
        ("NOO_MTLS_GATEWAY", "true".into()),
        ("NOO_TLS_CERT", format!("{pki}/gateway/gateway.crt")),
        ("NOO_TLS_KEY", format!("{pki}/gateway/gateway.key")),
        ("NOO_NATS_TLS", "true".into()),
        // No NOO_PG_TLS: since 2026-09-28 the Postgres service is TLS-only
        // unconditionally (docker-compose.cluster.yml) and every DSN
        // carries its transport. NOO_PG_SSLMODE stays as engine.py's
        // fallback for a DSN that names none.
        ("NOO_PG_SSLMODE", "verify-full".into()),
        ("REDIS_URL", "rediss://redis:6379".into()),
        ("NATS_URL", "tls://nats:4222".into()),
        ("NOO_LOKI_TLS", "true".into()),
    ] {
        ctx.update_env(k, &v);
    }
    // Topology URLs are declared ONLY for services this install's profile
    // deploys (doctrine: a duplicated declaration becomes a stale override
    // that silently wins). The old unconditional stunnel/vllm/loki writes
    // shipped dead endpoints to every standalone box — trellion 503'd on
    // embeddings and burned 701 retries on a vLLM that does not exist
    // (host8 live-fire, 2026-09-01). redis/nats above are always-on;
    // everything below depends on what actually runs here.
    apply_topology_env(ctx);
    let ctrl = ctx.read_env("CONTROLLER_URL");
    if ctrl.starts_with("http://gateway:") {
        ctx.update_env("CONTROLLER_URL", &ctrl.replacen("http://", "https://", 1));
    }
    ctx.state.tls_enabled = true;
}

fn install_ca_trust(ctx: &mut Ctx) {
    let ca_file = ctx.pki_dir.join("ca.crt");
    if !ca_file.exists() && !ctx.dry_run {
        return;
    }
    // The LINUX system store is the one that matters: it is what tailscaled
    // verifies the gateway against when `tailscale serve` proxies the
    // dashboard. The former Windows-store install (WSL2 certutil) served
    // browser trust, which MagicDNS made obsolete — the browser sees a
    // public ts.net cert. Installing only into Windows while a stale CA sat
    // in the Linux store 502'd the tailnet dashboard on 2026-08-06.
    ctx.info("The cluster CA goes into the Linux trust store — required for tailnet");
    ctx.info("access ('tailscale serve' verifies the gateway against it).");
    if !ctx.non_interactive && !ctx.asker.confirm("Install cluster CA into the Linux trust store?", true) {
        if ctx.state.ts_dnsname.is_empty() {
            ctx.info("Skipped. Run 'noo security trust-ca' later, or accept the browser warning.");
        } else {
            ctx.warn(
                "Skipped — the tailnet dashboard will 502 until the CA is installed: \
                 run 'noo security trust-ca', then 'sudo systemctl restart tailscaled'.",
            );
        }
        return;
    }
    if ctx.dry_run {
        ctx.dry("install ca.crt into the Linux trust store (update-ca-certificates)");
        return;
    }

    install_ca_linux(ctx, &ca_file);
}

fn install_ca_linux(ctx: &mut Ctx, ca_file: &Path) {
    let ca_dir = Path::new("/usr/local/share/ca-certificates");
    if !ca_dir.exists() {
        ctx.warn("Linux CA directory not found — cannot install CA trust");
        return;
    }
    let dest = ca_dir.join("mesh-cluster-ca.crt");
    // pkexec only for a person at a desktop who may be asked; everything
    // else is the seam's sudo, `-n` unless a person can answer (i267: this
    // is the call that hung take 14b at a password prompt under --ci).
    let may_prompt = ctx_sudo_may_prompt(ctx);
    let pkexec = may_prompt
        && Command::new("pkexec").arg("--version").output().is_ok()
        && std::env::var("DISPLAY").is_ok();
    let elevated = |_: &Ctx| if pkexec { Command::new("pkexec") } else { sudo_cmd(may_prompt) };
    let cp = elevated(ctx)
        .args(["cp"])
        .arg(ca_file)
        .arg(&dest)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let upd = cp
        && elevated(ctx)
            .arg("update-ca-certificates")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    if upd {
        ctx.success("Cluster CA installed into Linux trust store");
        // tailscaled reads the store at start — until it restarts, serve
        // keeps verifying against the OLD bundle and 502s.
        if !ctx.state.ts_dnsname.is_empty() {
            let _ = elevated(ctx)
                .args(["systemctl", "restart", "tailscaled"])
                .status();
            ctx.info("Restarted tailscaled to pick up the new CA.");
        }
    } else {
        ctx.warn(&format!(
            "Could not install CA. Run manually:\n    sudo cp {} {}\n    sudo update-ca-certificates",
            ca_file.display(),
            dest.display()
        ));
        sudo_refused(
            ctx,
            "cluster CA trust",
            &format!("sudo cp {} {} && sudo update-ca-certificates", ca_file.display(), dest.display()),
        );
    }
}

// ── Step 4: Storage ──────────────────────────────────────────────────────

struct Mount {
    path: String,
    fstype: String,
    free_gb: f64,
    total_gb: f64,
    is_system: bool,
    label: String,
}

pub fn storage(ctx: &mut Ctx) {
    let existing_root = {
        // Process env first: the fu53 guard tells operators to "set
        // NOO_DATA_ROOT" for a second install, and the dist rehearsal
        // proved read_env alone (the .env file) silently ignores that.
        let r = std::env::var("NOO_DATA_ROOT")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| ctx.read_env("NOO_DATA_ROOT"));
        if r == "." || r.is_empty() { String::new() } else { r }
    };

    ctx.progress("Scanning storage devices...");
    let mounts = detect_mounts();

    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let chosen_root: String;
    if mounts.is_empty() {
        ctx.warn("No suitable storage mounts detected (all < 5 GB).");
        chosen_root = if !existing_root.is_empty() {
            existing_root.clone()
        } else if let Some(found) = adoptable_root_on(&home) {
            found
        } else {
            crate::commands::data_root::DEFAULT_DATA_ROOT.to_string()
        };
        ctx.info(&format!("Using {chosen_root}"));
    } else {
        let rec_idx = pick_recommended(&mounts);
        if ctx.non_interactive {
            chosen_root = if !existing_root.is_empty() {
                existing_root.clone()
            } else if let Some(i) = rec_idx {
                default_root_for(&mounts[i], &home)
            } else {
                crate::commands::data_root::DEFAULT_DATA_ROOT.to_string()
            };
            ctx.info(&format!("Auto-selected storage: {chosen_root}"));
        } else {
            ctx.info("Detected storage locations:");
            for (i, m) in mounts.iter().enumerate() {
                let sys = if m.is_system { " (system)" } else { "" };
                let rec = if Some(i) == rec_idx { "  <-- recommended" } else { "" };
                ctx.info(&format!(
                    "  {}. {}{}  [{}]  {}  {:.0} GB free / {:.0} GB total{}",
                    i + 1,
                    m.path,
                    sys,
                    m.label,
                    m.fstype,
                    m.free_gb,
                    m.total_gb,
                    rec
                ));
            }
            let default_idx = rec_idx.map(|i| i + 1).unwrap_or(1);
            let choice = ctx.asker.ask_choice(
                &format!("  0. Custom path\nSelect a drive (1-{})", mounts.len()),
                default_idx,
                mounts.len(),
                true,
            );
            if choice == 0 {
                let d = if existing_root.is_empty() { crate::commands::data_root::DEFAULT_DATA_ROOT.to_string() } else { existing_root.clone() };
                chosen_root = ctx.asker.ask(&Prompt::new("Enter custom storage path").default(d));
            } else {
                let m = &mounts[choice - 1];
                let default_path = default_root_for(m, &home);
                if Path::new(&format!("{default_path}/postgres/PG_VERSION")).is_file() {
                    ctx.info(&format!(
                        "  Existing noomesh data found at {default_path} — the default ADOPTS it (fresh state, same database)."
                    ));
                }
                chosen_root = ctx.asker.ask(&Prompt::new("Storage root").default(default_path));
            }
        }
    }

    // Data-root policy: a dedicated, conventional `noo` directory. A root
    // that already holds this install's data is kept (moving it is the
    // operator's call) with a warning; a NEW choice that fails is replaced
    // by the standard location rather than written into .env.
    let mut chosen_root = chosen_root;
    if let Some((code, why)) = crate::commands::data_root::shape_problem(&chosen_root, false, "") {
        let holds_data = (!existing_root.is_empty() && chosen_root == existing_root)
            || Path::new(&format!("{chosen_root}/postgres/PG_VERSION")).is_file();
        if holds_data {
            ctx.warn(&format!(
                "data root {chosen_root} does not meet the data-root policy ({code}: {why}) — keeping it because it holds this install's data; move it to {} when convenient",
                crate::commands::data_root::DEFAULT_DATA_ROOT
            ));
        } else {
            ctx.warn(&format!("data root {chosen_root} refused ({code}: {why}) — using {}", crate::commands::data_root::DEFAULT_DATA_ROOT));
            chosen_root = crate::commands::data_root::DEFAULT_DATA_ROOT.to_string();
        }
    }

    // Instance isolation: every stateful compose volume is a
    // device-bind under NOO_DATA_ROOT, so a named instance sharing the
    // default root shares the DATABASES — the 2026-08-14 incident had a test
    // instance replaying WAL inside production's live postgres directory.
    // Auto-suffix rather than refuse: onboard is the one place that can
    // simply do the right thing.
    let scoped = instance_scoped_root(&chosen_root, &instance_name());
    if scoped != chosen_root {
        ctx.info(&format!(
            "Instance '{}': storage scoped to {scoped}",
            instance_name()
        ));
    }
    let chosen_root = scoped;

    // Docker data-root relocation
    ctx.progress("Checking Docker data root...");
    maybe_relocate_docker(ctx, &chosen_root, &home);

    ctx.update_env("NOO_DATA_ROOT", &chosen_root);
    ctx.state.data_root = chosen_root.clone();

    // The root FIRST: every directory below, postgres' included, is made
    // inside it. (Until now postgres' path was made before the root existed;
    // on the root-owned /var/lib/noo default that mkdir failed, silently, and
    // step 7 died on the daemon's "failed to mount local volume".)
    ctx.progress("Creating storage directories...");
    ensure_root_dir(ctx, Path::new(&chosen_root));

    // Encrypt at rest? (i10a) Asked BEFORE any state directory exists: a
    // "yes" makes the encrypted volume and points NOO_STATE_ROOT (and the
    // PKI) at it, so every directory below is made ON it and nothing is ever
    // written in the clear. A "yes" whose volume cannot be made stops the
    // wizard here, before any service starts. A "no" is recorded after the
    // services start.
    if !at_rest_choice(ctx, &chosen_root) {
        return;
    }

    // The sensitive state set binds under NOO_STATE_ROOT (default: the data
    // root, so unset changes nothing; i10a). This step does not choose it —
    // the operator or a later change sets it — it only follows it.
    let state_root = state_root_path(ctx, Path::new(&chosen_root)).to_string_lossy().into_owned();
    if state_root.trim_end_matches('/') != chosen_root.trim_end_matches('/') {
        ctx.info(&format!("State root (postgres, redis, nats, metrics, logs, app data): {state_root}"));
        ensure_root_dir(ctx, Path::new(&state_root));
    }

    // Postgres data path (NTFS → ext4 under home)
    ensure_pg_data_path(ctx, &state_root, &home);

    let failed = create_storage_dirs(ctx, Path::new(&chosen_root));
    record_storage_summary_failure(ctx, failed, &chosen_root);

    // Bind-mount summary
    ctx.info("Docker bind-mount paths:");
    for (label, sub) in [
        ("PostgreSQL", ctx.read_env("NOO_PG_DATA")),
        ("Redis", format!("{state_root}/redis")),
        ("NATS", format!("{state_root}/nats")),
        ("Ollama models", format!("{chosen_root}/ollama")),
        ("HF model cache", format!("{chosen_root}/hf-cache")),
        ("Application data", format!("{state_root}/noo-data")),
    ] {
        ctx.info(&format!("  {label:<18} {sub}"));
    }

    // Docker bind-mount test
    ctx.progress("Testing Docker bind mount access...");
    verify_bind_mount(ctx, &state_root);

    // User dirs + workspace
    configure_user_dirs(ctx);
}

/// i10a: detect a TPM and ask whether to encrypt data at rest.
///
/// - not a Linux controller: said plainly, nothing recorded;
/// - no usable TPM: explain why and how to enable one, record nothing (the
///   verify rows keep warning with the reason);
/// - a TPM: ask (default yes, `--ci` never asks) and print the disclosure
///   for the answer. "No" is kept in `ctx.state` and written after the
///   services start; "yes" runs `at_rest_volume::setup_fresh` (PR-C): the
///   encrypted state volume, before any service starts.
///
/// Returns false when the wizard must stop: the person said yes and the
/// volume could not be made. It never carries on unencrypted after a yes.
fn at_rest_choice(ctx: &mut Ctx, data_root: &str) -> bool {
    use crate::commands::at_rest::{self, Plan, TpmFacts};
    if ctx.state.mode == "worker" || !cfg!(target_os = "linux") {
        ctx.info("Encryption at rest is for Linux controllers; not supported on this machine.");
        return true;
    }
    if ctx.dry_run {
        ctx.dry("check for a TPM 2.0 and ask whether to encrypt data at rest (yes: create the encrypted state volume before any service starts)");
        return true;
    }
    let facts = TpmFacts::probe(Path::new("/"));
    let asker = &ctx.asker;
    let chosen = at_rest::plan(&facts, ctx.non_interactive, &mut || asker.confirm(at_rest::ONBOARD_PROMPT, true));
    match chosen {
        Plan::Unavailable => {
            ctx.warn(&format!("Your data cannot be encrypted at rest here: {}.", facts.unavailable_reason()));
            ctx.info(&at_rest::enable_hint(&facts));
            ctx.info(at_rest::DISCLOSURE_OFF);
        }
        Plan::Encrypt => return at_rest_encrypt_fresh(ctx, data_root),
        Plan::OptOut => {
            ctx.info(at_rest::DISCLOSURE_OFF);
            ctx.state.at_rest_opt_out = true;
        }
    }
    true
}

/// The "yes" of [`at_rest_choice`]: the encrypted state volume through
/// `at_rest_volume::setup_fresh`, whose step order is pinned by its tests.
fn at_rest_encrypt_fresh(ctx: &mut Ctx, data_root: &str) -> bool {
    use crate::commands::at_rest;
    use crate::commands::at_rest_volume::{self as vol, CreatePlan, FreshOutcome};
    let Some(user) = vol::operator_user() else {
        return at_rest_stop(ctx, "onboard runs as root, so there is no operator account to hand the encrypted state to");
    };
    let pki_from = ctx
        .pki_dir
        .join("ca.crt")
        .is_file()
        .then(|| std::fs::canonicalize(&ctx.pki_dir).ok())
        .flatten()
        .map(|p| p.to_string_lossy().into_owned());
    let plan = CreatePlan {
        data_root: data_root.trim_end_matches('/').to_string(),
        size_gib: vol::MIN_SIZE_GIB,
        user,
        pcrs: "auto".into(),
        subdirs: vol::state_subdir_specs(),
        age_key: vol::age_key_to_escrow(&ctx.read_env("SOPS_AGE_KEY_FILE")),
        pki_from,
        defer: false,
    };
    ctx.progress("Creating the encrypted state volume (LUKS2, unlocked by this machine's TPM)...");
    let outcome = {
        let mut io = OnboardFresh { ctx: &mut *ctx };
        vol::setup_fresh(&mut io, plan)
    };
    match outcome {
        Ok(FreshOutcome::Created { state_root, acknowledged, deferred }) => {
            ctx.success(&format!("Encrypted state volume open and mounted at {state_root}; the state set and the PKI live on it"));
            ctx.info(at_rest::DISCLOSURE_ON);
            ctx.info("Data written before this step can linger on an SSD: the keys and secrets are rotated after sealing (i10a).");
            ctx.state.at_rest_recovery_ack = acknowledged;
            if deferred {
                ctx.warn("No recovery key yet: this wizard has no private terminal to show it on. The volume unlocks by this machine's TPM only until one is made with `noo security at-rest recovery-key`.");
            } else if !acknowledged {
                ctx.warn("The recovery key was not acknowledged: verify warns until a new one is made and stored off this machine.");
            }
            true
        }
        Ok(FreshOutcome::AlreadyThere { state_root }) => {
            ctx.info(&format!("The encrypted state volume is already open at {state_root}."));
            ctx.info(at_rest::DISCLOSURE_ON);
            true
        }
        Ok(FreshOutcome::Skipped(why)) => {
            ctx.warn(&format!("Encryption at rest was not set up: {why}."));
            ctx.info(at_rest::DISCLOSURE_OFF);
            true
        }
        Err(e) => at_rest_stop(ctx, &e),
    }
}

/// Stop the wizard after a "yes" that could not be carried out. Nothing has
/// started; nothing is left half-switched (`setup_fresh` points `.env` at
/// the volume only after it exists).
fn at_rest_stop(ctx: &mut Ctx, why: &str) -> bool {
    ctx.error(&format!("Encryption at rest could not be set up: {why}"));
    ctx.info("Nothing was started. Fix the cause and re-run: noo onboard --only storage — or answer no to keep your data unencrypted on disk (recorded).");
    ctx.state.hard_failures.push(format!("at rest: the encrypted state volume was not created ({why})"));
    ctx.state.interrupted = true;
    false
}

/// The wizard's side of `at_rest_volume::FreshSteps`.
struct OnboardFresh<'c, 'a> {
    ctx: &'c mut Ctx<'a>,
}

impl crate::commands::at_rest_volume::FreshSteps for OnboardFresh<'_, '_> {
    fn existing_volume(&self) -> Option<crate::commands::at_rest_volume::Volume> {
        crate::commands::at_rest_volume::read_volume()
    }

    fn state_in_use(&self) -> Option<String> {
        let root = self.ctx.state.data_root.clone();
        let state = crate::commands::data_root::state_root_of(Some(self.ctx.read_env("NOO_STATE_ROOT").as_str()), &root);
        let mut dirs: Vec<String> = STATE_SUBDIRS.iter().map(|n| format!("{}/{n}", state.trim_end_matches('/'))).collect();
        let pg = self.ctx.read_env("NOO_PG_DATA");
        if !pg.trim().is_empty() {
            dirs.push(pg);
        }
        dirs.into_iter().find(|d| std::fs::read_dir(d).map(|mut it| it.next().is_some()).unwrap_or(false))
    }

    fn free_bytes(&self, path: &str) -> Option<u64> {
        crate::commands::at_rest_volume::free_bytes(path)
    }

    fn can_show_secret(&self) -> bool {
        !self.ctx.non_interactive
            && self.ctx.ui.inherit_stdio()
            && super::prompt::stdin_is_tty()
            && super::prompt::stdout_is_tty()
    }

    fn create_volume(&mut self, plan: &crate::commands::at_rest_volume::CreatePlan) -> Result<crate::commands::at_rest_volume::Created, String> {
        let console = self.ctx.ui.inherit_stdio();
        let hostd = std::env::var("NOO_HOSTD_BIN")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| crate::commands::at_rest_volume::HOSTD_BIN.to_string());
        if !Path::new(&hostd).is_file() {
            if !console {
                return Err(format!(
                    "{hostd} is not installed and this wizard cannot run sudo at a terminal — run noo onboard --only storage from a terminal"
                ));
            }
            obtain_hostd_binary(self.ctx)?;
        }
        let argv = crate::commands::at_rest_volume::hostd_argv(&hostd, plan);
        self.ctx.info(&format!("running: sudo {}", argv.join(" ")));
        let sudo_n = self.ctx.non_interactive || !console;
        let (res, stderr) = crate::commands::at_rest_volume::run_hostd(&argv, sudo_n, console);
        for l in stderr.lines().filter(|l| !l.trim().is_empty()) {
            self.ctx.raw(&format!("    {l}"));
        }
        res
    }

    fn show_recovery_key(&mut self, key: &str) -> bool {
        self.ctx.warn(crate::commands::at_rest_volume::RECOVERY_KEY_WARNING);
        if !self.ctx.ui.reveal_secret("Recovery key for the encrypted state volume", key) {
            return false;
        }
        loop {
            let first = self.ctx.asker.ask(&Prompt::new("Type the FIRST group of the recovery key (empty to skip)"));
            if first.trim().is_empty() {
                if self.ctx.asker.confirm("Continue WITHOUT confirming you stored the recovery key", false) {
                    return false;
                }
                continue;
            }
            let last = self.ctx.asker.ask(&Prompt::new("Type the LAST group of the recovery key"));
            if crate::commands::at_rest_volume::retyped_ok(key, &first, &last) {
                self.ctx.success("Recovery key handed over (no copy on this machine).");
                return true;
            }
            self.ctx.warn("Those groups do not match the key above — read it again and retype them.");
        }
    }

    fn read_env(&self, key: &str) -> String {
        self.ctx.read_env(key)
    }

    fn set_env(&mut self, key: &str, value: &str) {
        self.ctx.update_env(key, value);
        // Later steps in this same run read these from the process
        // environment (pki::pki_dir, the launcher's env) and from ctx.
        std::env::set_var(key, value);
        if key == "NOO_PKI_DIR" {
            self.ctx.pki_dir = PathBuf::from(value);
        }
    }
}

/// Record the at-rest opt-out chosen in the storage step, now that the
/// gateway is up. A failure is a warning with the retry command, not a hard
/// failure: the person's answer is not lost, only not yet on record.
pub fn at_rest_record(ctx: &mut Ctx) {
    at_rest_record_recovery_ack(ctx);
    if !ctx.state.at_rest_opt_out {
        return;
    }
    if ctx.dry_run {
        ctx.dry("record the at-rest opt-out in the gateway");
        return;
    }
    if !ctx.state.services_started {
        ctx.warn("The gateway is not running, so your choice not to encrypt at rest was NOT recorded.");
        ctx.info("Once the stack is up: noo security at-rest opt-out");
        return;
    }
    match crate::http::post_json_try(
        ctx.g,
        "/api/settings/flags/set",
        &serde_json::json!({"key": crate::commands::at_rest::SETTING, "value": true}),
        true,
        15,
    ) {
        Ok(_) => ctx.success("Recorded: you accept unencrypted data at rest (noo security at-rest status shows it)."),
        Err(e) => {
            ctx.warn(&format!("Could not record your at-rest choice ({e})."));
            ctx.info("Record it yourself: noo security at-rest opt-out");
        }
    }
}

/// Record that the person acknowledged the state volume's recovery key
/// (shown in the storage step), now that the gateway is up. Person-only on
/// the gateway side, so it carries the operator's own login.
fn at_rest_record_recovery_ack(ctx: &mut Ctx) {
    if !ctx.state.at_rest_recovery_ack {
        return;
    }
    if ctx.dry_run {
        ctx.dry("record the recovery-key acknowledgement in the gateway");
        return;
    }
    if !ctx.state.services_started {
        ctx.warn("The gateway is not running, so your recovery-key acknowledgement was NOT recorded; verify will warn about it.");
        return;
    }
    match crate::http::post_json_try(
        ctx.g,
        "/api/settings/flags/set",
        &serde_json::json!({"key": crate::commands::at_rest_volume::RECOVERY_SETTING, "value": true}),
        true,
        15,
    ) {
        Ok(_) => ctx.success("Recorded: you stored the recovery key off this machine."),
        Err(e) => ctx.warn(&format!("Could not record your recovery-key acknowledgement ({e}); verify will warn about it.")),
    }
}

/// Mount targets from a /proc/mounts listing that could hold a data root:
/// a real filesystem, mounted read-write, somewhere data belongs. Pure so
/// it can be tested against a synthetic listing.
///
/// The read-write and prefix checks exist because of the 2026-09-27
/// newcomer rehearsal: inside a container, Docker bind-mounts
/// `/etc/resolv.conf` as a FILE on the host's ext4, which has the most free
/// space of anything visible, so `--ci` auto-selected `/etc/resolv.conf/noo`
/// and every storage directory failed; the pass before it picked a
/// read-only bind mount the same way. Both are real shapes on real boxes
/// too (LXC bind-mounts `/etc/hostname`; a read-only volume or ISO mount).
fn mount_candidates_from(proc_mounts: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    for line in proc_mounts.lines() {
        let mut it = line.split_whitespace();
        let (Some(_dev), Some(target), Some(fstype), opts) = (it.next(), it.next(), it.next(), it.next().unwrap_or("")) else { continue };
        if !matches!(fstype, "ext4" | "ext3" | "ext2" | "xfs" | "btrfs" | "zfs" | "ntfs" | "ntfs3" | "exfat" | "9p") {
            continue;
        }
        if opts.split(',').any(|o| o == "ro") {
            continue; // nothing can be created there
        }
        if ["/boot", "/snap", "/var/lib/docker", "/run", "/etc", "/proc", "/sys", "/dev"]
            .iter()
            .any(|p| target == *p || target.starts_with(&format!("{p}/")))
        {
            continue;
        }
        candidates.push(target.replace("\\040", " "));
    }
    candidates
}

fn detect_mounts() -> Vec<Mount> {
    let mut seen_dev = std::collections::HashSet::new();
    // Real mounts from /proc/mounts FIRST (first-contact finding #8: a 1TB
    // drive at /srv/storage was invisible — the old hardcoded candidate
    // list only ever probed /srv itself, which sits on the root device).
    // Then the historical candidates as a fallback for bind-ish layouts.
    let mut candidates: Vec<String> = std::fs::read_to_string("/proc/mounts")
        .map(|m| mount_candidates_from(&m))
        .unwrap_or_default();
    for letter in "cdefghijklmnopqrstuvwxyz".chars() {
        let p = format!("/mnt/{letter}");
        if Path::new(&p).is_dir() {
            candidates.push(p);
        }
    }
    for p in ["/", "/home", "/data", "/opt", "/srv"] {
        if Path::new(p).is_dir() {
            candidates.push(p.to_string());
        }
    }
    let mut mounts = Vec::new();
    for path in candidates {
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        if !meta.is_dir() {
            continue; // a bind-mounted file is a mount point too
        }
        let dev = std::os::unix::fs::MetadataExt::dev(&meta);
        if !seen_dev.insert(dev) {
            continue;
        }
        let Some((total_gb, free_gb)) = disk_usage(&path) else { continue };
        if total_gb < 5.0 {
            continue;
        }
        let fstype = fstype_of(&path);
        let is_system = path == "/" || path == "/mnt/c";
        let label = if path.starts_with("/mnt/") && path.len() == 6 {
            format!("Drive {}:", path.chars().last().unwrap().to_ascii_uppercase())
        } else if path == "/" {
            "Root filesystem".to_string()
        } else {
            Path::new(&path).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or(path.clone())
        };
        mounts.push(Mount { path, fstype, free_gb, total_gb, is_system, label });
    }
    // non-system first, then free space desc
    mounts.sort_by(|a, b| {
        a.is_system
            .cmp(&b.is_system)
            .then(b.free_gb.partial_cmp(&a.free_gb).unwrap_or(std::cmp::Ordering::Equal))
    });
    mounts
}

fn disk_usage(path: &str) -> Option<(f64, f64)> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let frsize = s.f_frsize as f64;
    let gib = 1024.0 * 1024.0 * 1024.0;
    let total = s.f_blocks as f64 * frsize / gib;
    let free = s.f_bavail as f64 * frsize / gib;
    Some((total, free))
}

fn fstype_of(path: &str) -> String {
    let Ok(text) = std::fs::read_to_string("/proc/mounts") else { return "unknown".into() };
    let mut best = String::new();
    let mut best_len = 0;
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let mp = parts[1];
            if path.starts_with(mp) && mp.len() > best_len {
                best = parts[2].to_string();
                best_len = mp.len();
            }
        }
    }
    if best.is_empty() { "unknown".into() } else { best }
}

fn is_ntfs(path: &str) -> bool {
    matches!(fstype_of(path).as_str(), "9p" | "drvfs")
}

fn pick_recommended(mounts: &[Mount]) -> Option<usize> {
    for (i, m) in mounts.iter().enumerate() {
        if !m.is_system && m.free_gb > 20.0 {
            return Some(i);
        }
    }
    for (i, m) in mounts.iter().enumerate() {
        if m.path == "/" {
            return Some(i);
        }
    }
    if mounts.is_empty() { None } else { Some(0) }
}

fn default_root_for(m: &Mount, home: &str) -> String {
    // The mount that HOLDS $HOME gets the home-relative default: `/home`
    // on its own partition used to yield `/home/noo`, which the user
    // cannot create, so the wizard fell to sudo and left root-owned
    // models/, hf-cache/ and ollama/ (paper rehearsal, 2026-09-24).
    let mount = m.path.trim_end_matches('/');
    let holds_home = m.path == "/" || home == mount || home.starts_with(&format!("{mount}/"));
    let base = if holds_home { home } else { m.path.as_str() };
    // Fresh STATE over surviving DATA is the supported reinstall shape:
    // if this drive already holds a populated noomesh data root, adopting
    // it is the default — a bare "<drive>/noo" default here re-pointed a
    // reinstall at an empty tree while the operator's database sat one
    // directory over (2026-09-01, twice).
    if let Some(found) = adoptable_root_on(base) {
        return found;
    }
    // A new root follows the data-root policy: never inside a home
    // directory or on a Windows drive; the standard location otherwise.
    let candidate = format!("{}/noo", m.path.trim_end_matches('/'));
    if holds_home || crate::commands::data_root::shape_problem(&candidate, false, "").is_some() {
        return crate::commands::data_root::DEFAULT_DATA_ROOT.to_string();
    }
    candidate
}

/// An existing data root on this mount, proven by postgres/PG_VERSION.
fn adoptable_root_on(base: &str) -> Option<String> {
    for name in ["noomesh", "noo", "pai"] {
        let cand = format!("{base}/{name}");
        if Path::new(&format!("{cand}/postgres/PG_VERSION")).is_file() {
            return Some(cand);
        }
    }
    None
}

fn ensure_pg_data_path(ctx: &mut Ctx, chosen_root: &str, home: &str) {
    if !is_ntfs(chosen_root) {
        let pg = format!("{chosen_root}/postgres");
        if !ctx.dry_run {
            // A failure here is NOT swallowed: `create_storage_dirs` retries it
            // (with sudo) as the "postgres" floor entry and counts it failed.
            if std::fs::create_dir_all(&pg).is_ok() {
                ensure_pg_data_ownership(&pg);
            }
        }
        ctx.update_env("NOO_PG_DATA", &pg);
        return;
    }
    let pg = format!("{home}/noo/postgres");
    if !ctx.dry_run {
        let _ = std::fs::create_dir_all(&pg);
        ensure_pg_data_ownership(&pg);
    }
    ctx.update_env("NOO_PG_DATA", &pg);
    ctx.warn(&format!("Storage root is on NTFS ({}) — PostgreSQL needs POSIX perms.", fstype_of(chosen_root)));
    ctx.info(&format!("PostgreSQL data redirected to: {pg} (ext4)"));
}

/// The chainguard postgres runs as uid 70 and must OWN its data dir —
/// initdb dies with "could not change permissions … Operation not
/// permitted" on a dir the wizard's user created (fixed by hand during the
/// live cutover, reproduced verbatim by the sandbox rehearsal). chown
/// through a throwaway container: needs only docker-group membership, no
/// sudo, and works whoever runs the wizard. Only applied while the dir is
/// EMPTY — an initialized cluster's ownership is never touched.
pub(crate) fn ensure_pg_data_ownership(pg: &str) {
    ensure_dir_ownership(pg, "70:70");
}

/// Chown an EMPTY service data dir to the uid its container runs as, via a
/// throwaway container (no sudo needed — docker-group membership does it).
/// The hardened images run nonroot and cannot fix permissions themselves:
/// postgres (uid 70) dies in initdb, and prometheus (65532) PANICS writing
/// queries.active into a dir owned by whoever ran the wizard — the sandbox
/// --dist rehearsal hit both. Never touches a non-empty dir: initialized
/// data keeps whatever ownership it has.
pub(crate) fn ensure_dir_ownership(dir: &str, owner: &str) {
    let empty = std::fs::read_dir(dir).map(|mut d| d.next().is_none()).unwrap_or(false);
    if !empty {
        return;
    }
    let _ = Command::new("docker")
        .args(["run", "--rm", "-v", &format!("{dir}:/d"), "alpine", "chown", owner, "/d"])
        .output();
}

/// Nonroot service uids per data subdir (observed on the live images:
/// chainguard/dhi redis, grafana, loki, prometheus all run as 65532).
/// Dirs not listed stay owned by the wizard's user (host-side tooling
/// reads/writes them: models, hf-cache, noo-data, ollama, nats-root-image).
pub(crate) fn subdir_owner(name: &str) -> Option<&'static str> {
    match name {
        "redis" | "prometheus" | "grafana" | "loki" | "tempo" => Some("65532:65532"),
        // The chainguard postgres runs as uid 70 and initdb needs to own it.
        "postgres" => Some("70:70"),
        _ => None,
    }
}

/// The directories under `root` this step creates: every host directory the
/// composed config (`--profile controller`, the profile step 7 starts)
/// bind-mounts under the data root — the preflight's own derivation,
/// `bind_sources::directory_sources_under` — plus the `STORAGE_SUBDIRS`
/// floor (which names `postgres`, the device of the `postgres-data` volume — a named volume, not a bind). When the
/// config cannot be rendered (no docker, a dry run) the floor alone is used:
/// ABSENT answer, not a failed step; step 7's preflight still refuses a
/// source this list missed, naming it.
fn storage_subdirs(ctx: &Ctx, root: &Path) -> Vec<String> {
    let mut names: std::collections::BTreeSet<String> = STORAGE_SUBDIRS.iter().map(|s| s.to_string()).collect();
    // Postgres' device is NOO_PG_DATA, which `ensure_pg_data_path` points
    // OUTSIDE the root on an NTFS root (ext4 under $HOME): then `<root>/postgres`
    // is not the volume's device and must not be made here.
    let pg = ctx.read_env("NOO_PG_DATA");
    let pg = pg.trim_end_matches('/');
    let root_s0 = root.to_string_lossy();
    let pg_elsewhere = !pg.is_empty() && pg != format!("{}/postgres", root_s0.trim_end_matches('/'));
    if pg_elsewhere {
        names.remove("postgres");
    }
    let (code, out) = sh::run_compose(ctx, &["--profile", "controller", "config", "--format", "json"]);
    let cfg = (code == 0)
        .then(|| serde_json::Deserializer::from_str(&out).into_iter::<serde_json::Value>().next())
        .flatten()
        .and_then(Result::ok);
    if let Some(cfg) = cfg {
        let root_s = root.to_string_lossy();
        for src in crate::commands::bind_sources::directory_sources_under(&cfg, &root_s) {
            if pg_elsewhere && src == format!("{}/postgres", root_s.trim_end_matches('/')) {
                continue;
            }
            if let Ok(rel) = Path::new(&src).strip_prefix(root_s.trim_end_matches('/')) {
                names.insert(rel.to_string_lossy().into_owned());
            }
        }
    }
    names.into_iter().collect()
}

/// The root of the sensitive state set for this install: `NOO_STATE_ROOT`
/// from `.env` when set, else `root` itself (i10a: unset = no change).
fn state_root_path(ctx: &Ctx, root: &Path) -> PathBuf {
    PathBuf::from(crate::commands::data_root::state_root_of(
        Some(ctx.read_env("NOO_STATE_ROOT").as_str()),
        &root.to_string_lossy(),
    ))
}

/// Every (name, full path) this step creates: [`storage_subdirs`] under the
/// data root, except that when `NOO_STATE_ROOT` names a DIFFERENT root the
/// state set ([`STATE_SUBDIRS`]) is created under it instead (postgres only
/// when `NOO_PG_DATA` points there; elsewhere it is not ours to make).
/// Identical to the old per-root list while `NOO_STATE_ROOT` is unset.
fn storage_targets(ctx: &Ctx, root: &Path) -> Vec<(String, PathBuf)> {
    let state = state_root_path(ctx, root);
    let trim = |p: &Path| p.to_string_lossy().trim_end_matches('/').to_string();
    let separated = trim(&state) != trim(root);
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    for name in storage_subdirs(ctx, root) {
        if separated && STATE_SUBDIRS.contains(&name.as_str()) {
            continue;
        }
        let target = root.join(&name);
        out.push((name, target));
    }
    if separated {
        let pg = ctx.read_env("NOO_PG_DATA");
        let pg = pg.trim_end_matches('/');
        let pg_elsewhere = !pg.is_empty() && pg != format!("{}/postgres", trim(&state));
        for name in STATE_SUBDIRS {
            if *name == "postgres" && pg_elsewhere {
                continue;
            }
            out.push((name.to_string(), state.join(name)));
        }
    }
    out
}

/// Returns how many subdirectories could not be created.
/// Create the data root itself, owned by the operator. /var/lib/noo needs
/// sudo to create, but a sudo `mkdir -p` of the subdirectories leaves them
/// root-owned (paper rehearsal, 2026-09-24), so the root is made with
/// `install -d -o <uid> -g <gid> -m 0755` and everything below it is created
/// as the operator. 0755, not 0750: container uids (postgres runs as 70)
/// traverse it; the policy only forbids group/other WRITE.
fn ensure_root_dir(ctx: &mut Ctx, root: &Path) {
    if root.exists() || ctx.dry_run {
        return;
    }
    if std::fs::create_dir_all(root).is_ok() {
        return;
    }
    let id = |flag: &str| {
        Command::new("id").arg(flag).output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let (Some(uid), Some(gid)) = (id("-u"), id("-g")) else { return };
    let ok = ctx_sudo(ctx).args(["install", "-d", "-o", &uid, "-g", &gid, "-m", "0755"]).arg(root)
        .status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        ctx.warn(&format!("could not create {} (sudo install -d failed); create it owned by you and re-run", root.display()));
        sudo_refused(ctx, "data root", &format!("sudo install -d -o {uid} -g {gid} -m 0755 {}", root.display()));
    }
}

/// True once a hard failure about storage is on the verdict. Storage is one
/// action: the step, its summary and the services step's re-check all
/// report the same missing directories, so the FIRST failure is the one
/// the closing block lists (i276).
fn storage_failure_recorded(ctx: &Ctx) -> bool {
    ctx.state.hard_failures.iter().any(|f| f.starts_with("storage"))
}

/// The storage step's own summary failure, unless a refusal for the same
/// action is already recorded.
fn record_storage_summary_failure(ctx: &mut Ctx, failed: usize, chosen_root: &str) {
    if failed == 0 || storage_failure_recorded(ctx) {
        return;
    }
    // Every stateful service bind-mounts under this root; carrying on
    // only moves the failure to `noo stack start`, and under --ci nobody
    // is watching the warning. Record it so the wizard exits non-zero.
    ctx.state.hard_failures.push(format!(
        "storage: {failed} director{} under {chosen_root} could not be created (set NOO_DATA_ROOT to a writable directory)",
        if failed == 1 { "y" } else { "ies" }
    ));
}

fn create_storage_dirs(ctx: &mut Ctx, root: &Path) -> usize {
    let (mut created, mut existing, mut failed) = (0, 0, 0);
    for (name, target) in &storage_targets(ctx, root) {
        if target.exists() {
            existing += 1;
            continue;
        }
        if ctx.dry_run {
            created += 1;
            continue;
        }
        match std::fs::create_dir_all(target) {
            Ok(_) => {
                created += 1;
                if let Some(owner) = subdir_owner(name.as_str()) {
                    ensure_dir_ownership(&target.to_string_lossy(), owner);
                }
            }
            Err(_) => {
                // retry with sudo — `-n` unless a person can answer (i267)
                let ok = ctx_sudo(ctx)
                    .args(["mkdir", "-p"])
                    .arg(target)
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if ok {
                    created += 1;
                } else {
                    failed += 1;
                }
            }
        }
    }
    let detail = format!("{created} created, {existing} already exist, {failed} failed");
    if failed > 0 {
        ctx.warn(&format!("Storage directories ({detail}) under {}", root.display()));
        if !storage_failure_recorded(ctx) {
            sudo_refused(ctx, &format!("storage ({failed} director(ies) under {})", root.display()), &format!("sudo mkdir -p {}/<each missing directory>, then: noo onboard --only storage", root.display()));
        }
    } else {
        ctx.success(&format!("Storage directories ({detail}) under {}", root.display()));
    }
    failed
}

fn verify_bind_mount(ctx: &mut Ctx, root: &str) {
    if ctx.dry_run {
        ctx.dry(&format!("docker run --rm -v {root}/noo-data:/test alpine touch /test/.bind-mount-ok"));
        return;
    }
    if !sh::docker_image_exists("alpine:latest") {
        ctx.progress("Pulling alpine image for bind-mount test...");
        let _ = sh::docker(&["pull", "alpine:latest"]);
    }
    let test_dir = format!("{root}/noo-data");
    let vol = format!("{test_dir}:/test");
    let (code, out) = sh::docker(&["run", "--rm", "-v", &vol, "alpine:latest", "touch", "/test/.bind-mount-ok"]);
    let marker = Path::new(&test_dir).join(".bind-mount-ok");
    let _ = std::fs::remove_file(marker);
    if code == 0 {
        ctx.success("Docker can bind-mount to the storage location");
    } else {
        ctx.warn(&format!("Docker bind-mount test failed: {}", out.trim()));
        ctx.info(&format!("Check Docker file sharing / permissions for {root}"));
    }
}

fn maybe_relocate_docker(ctx: &mut Ctx, chosen_root: &str, _home: &str) {
    let (code, out) = sh::docker(&["info", "--format", "{{.DockerRootDir}}"]);
    if code != 0 {
        return;
    }
    let docker_root = out.trim().to_string();
    let on_system = docker_root.starts_with("/var/lib/docker") || docker_root.starts_with("/mnt/c");
    if !on_system {
        return;
    }
    let parent = Path::new(chosen_root).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let target = format!("{parent}/docker");
    if target.starts_with("/var/lib") || target.starts_with("/mnt/c") {
        return;
    }
    if docker_root == target {
        ctx.info(&format!("Docker data-root already set to {target}"));
        return;
    }
    // Same disk → a move buys nothing. On a single-disk Ubuntu box
    // /var/lib/docker IS "the system drive" and ~/docker is the same disk,
    // so the wizard proposed a move that changed nothing except the
    // daemon.json it overwrote on the way (paper rehearsal, 2026-09-24).
    if same_device(&docker_root, &parent) {
        ctx.info(&format!("Docker data is on the same disk as {chosen_root} — leaving it at {docker_root}"));
        return;
    }
    if ctx.dry_run {
        ctx.dry(&format!("merge data-root={target} into /etc/docker/daemon.json and restart Docker (via sudo)"));
        ctx.state.docker_root_changed = true;
        return;
    }
    // A written-but-not-restarted data-root is a reboot bomb: the services
    // step pulls gigabytes onto the OLD root, and the next boot starts Docker
    // on an empty one with every image gone. So the move is offered only
    // where the wizard can restart Docker right now — an interactive TTY —
    // and never under --ci, which used to auto-accept it and skip the restart.
    if ctx.non_interactive || !ctx.ui.inherit_stdio() || !super::prompt::stdin_is_tty() {
        ctx.info(&format!(
            "Docker data is on the system drive ({docker_root}). To move it: set \"data-root\": \"{target}\" in /etc/docker/daemon.json and restart Docker BEFORE noo stack start"
        ));
        return;
    }
    // Guard: many images → refuse (would orphan them)
    let (_, imgs) = sh::docker(&["images", "-q"]);
    let image_count = imgs.lines().filter(|l| !l.trim().is_empty()).count();
    if image_count > 3 {
        ctx.warn(&format!(
            "Docker already has {image_count} images — changing data-root would hide them. Skipping (migrate manually)."
        ));
        return;
    }
    if !ctx.asker.confirm(
        &format!("Docker data is on the system drive ({docker_root}). Move it to {target} and restart Docker now? (uses sudo)"),
        true,
    ) {
        return;
    }
    let existing = match read_daemon_json() {
        Ok(s) => s,
        Err(e) => {
            ctx.warn(&format!("{e} — leaving Docker's data root where it is"));
            return;
        }
    };
    // MERGE, never overwrite: step 1's nvidia-container-toolkit install had
    // just written the `nvidia` runtime into this file, and the old
    // `{"data-root": …}` payload deleted it along with any log rotation.
    let payload = match merge_daemon_json(&existing, &target) {
        Ok(p) => p,
        Err(e) => {
            ctx.warn(&format!("{e} — leaving Docker's data root where it is"));
            return;
        }
    };
    if !write_daemon_json(ctx, &payload) {
        ctx.warn("Failed to write /etc/docker/daemon.json");
        return;
    }
    let ok = ctx_sudo(ctx).args(["systemctl", "restart", "docker"])
        .status().map(|s| s.success()).unwrap_or(false);
    if ok {
        ctx.success(&format!("Docker data-root set to {target} — Docker restarted"));
        ctx.state.docker_root_changed = true;
    } else {
        ctx.error(&format!(
            "/etc/docker/daemon.json now names {target} but Docker did NOT restart — run: sudo systemctl restart docker BEFORE noo stack start, or the stack pulls onto the old root and vanishes on reboot"
        ));
    }
}

/// The block device under the nearest existing ancestor of `path`.
fn device_of(path: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let mut p = Path::new(path);
    loop {
        if let Ok(m) = std::fs::metadata(p) {
            return Some(m.dev());
        }
        p = p.parent()?;
    }
}

fn same_device(a: &str, b: &str) -> bool {
    matches!((device_of(a), device_of(b)), (Some(x), Some(y)) if x == y)
}

/// The daemon's current config, or why it could not be read. An unreadable
/// file is a reason to stop, not an empty file: treating it as empty is
/// exactly the overwrite this exists to prevent.
fn read_daemon_json() -> Result<String, String> {
    const P: &str = "/etc/docker/daemon.json";
    match std::fs::read_to_string(P) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(_) => sudo_cmd(false).args(["cat", P]).output().ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .ok_or_else(|| format!("{P} exists but could not be read (even via sudo -n)")),
    }
}

/// `existing` with `data-root` set to `target`, every other key kept.
fn merge_daemon_json(existing: &str, target: &str) -> Result<String, String> {
    let mut v: serde_json::Value = if existing.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(existing)
            .map_err(|e| format!("/etc/docker/daemon.json is not valid JSON ({e}); fix it by hand first"))?
    };
    let obj = v.as_object_mut().ok_or_else(|| "/etc/docker/daemon.json is not a JSON object".to_string())?;
    obj.insert("data-root".to_string(), serde_json::Value::String(target.to_string()));
    let mut out = serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?;
    out.push('\n');
    Ok(out)
}

fn write_daemon_json(ctx: &Ctx, payload: &str) -> bool {
    let mut child = match ctx_sudo(ctx)
        .args(["tee", "/etc/docker/daemon.json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    if let Some(stdin) = child.stdin.as_mut() {
        if crate::child_stdin::write_child_stdin(stdin, payload.as_bytes()).is_err() {
            return false;
        }
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

fn configure_user_dirs(ctx: &mut Ctx) {
    let mut read_hosts: Vec<String> = Vec::new();
    let mut workspace: Option<String> = None;

    if ctx.non_interactive {
        // CI: NOO_USER_DIRS (colon-separated) for read dirs, NOO_WORKSPACE_DIR for workspace.
        let dirs = std::env::var("NOO_USER_DIRS").unwrap_or_default();
        read_hosts = dirs.split(':').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
        let ws = std::env::var("NOO_WORKSPACE_DIR").unwrap_or_default();
        if !ws.is_empty() && Path::new(&ws).is_dir() {
            workspace = Some(ws);
        }
    } else {
        ctx.info("");
        ctx.info("Directories for AI file access (read-only, auto-ingested).");
        ctx.info("  (e.g. /home/you/notes, /srv/docs — anything worth searching/asking about)");
        if ctx.asker.confirm("Add directories the AI can read?", false) {
            loop {
                let p = ctx.asker.ask(&Prompt::new("Add directory path (empty to finish)"));
                if p.is_empty() {
                    break;
                }
                if Path::new(&p).is_dir() {
                    read_hosts.push(p);
                } else {
                    ctx.warn(&format!("Skipping (not found): {p}"));
                }
            }
        }
        ctx.info("");
        ctx.info("AI Workspace (read-write, NOT auto-ingested).");
        // Reconfigure remembers the previous workspace (finding #23), and a
        // typo'd path is caught HERE instead of shipping as a dead mount
        // (finding #24: "/src/storage/..." was accepted, create_dir_all
        // failed silently, and the wrong path went into the compose override).
        let prev_ws = yamlcfg::read_yaml_workspace(ctx);
        // Example path from the real data root
        // the bare prompt gave nothing to pattern a path against). Empty
        // still means skip — the example is copy, not a default.
        let ws_example = {
            let root = ctx.read_env("NOO_DATA_ROOT");
            if root.is_empty() {
                "/srv/storage/noo/ai-workspace".to_string()
            } else {
                format!("{}/ai-workspace", root.trim_end_matches('/'))
            }
        };
        let ws_label = format!("Workspace directory path (empty to skip; e.g. {ws_example})");
        loop {
            let mut prompt = Prompt::new(&ws_label);
            if let Some(d) = &prev_ws {
                prompt = prompt.default(d.clone());
            }
            let ws = ctx.asker.ask(&prompt);
            if ws.is_empty() {
                break;
            }
            if !Path::new(&ws).is_dir() && !ctx.dry_run {
                if !ctx.asker.confirm(&format!("{ws} does not exist — create it?"), true) {
                    continue; // re-prompt (likely a typo)
                }
                if let Err(e) = std::fs::create_dir_all(&ws) {
                    ctx.warn(&format!("could not create {ws}: {e} — check the path for typos"));
                    if ctx.non_interactive {
                        break; // no way to correct it; skip rather than loop
                    }
                    continue;
                }
            }
            workspace = Some(ws);
            break;
        }
    }

    // Build read-dir mount mappings (unique container paths under /user-dirs).
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut entries: Vec<(String, String)> = Vec::new();
    for h in &read_hosts {
        let base = Path::new(h.trim_end_matches(['/', '\\']))
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "dir".to_string());
        let mount = match seen.get(&base).copied() {
            None => {
                seen.insert(base.clone(), 1);
                format!("/user-dirs/{base}")
            }
            Some(n) => {
                seen.insert(base.clone(), n + 1);
                format!("/user-dirs/{base}-{}", n + 1)
            }
        };
        entries.push((h.clone(), mount));
    }

    let workspace_pair = workspace.as_ref().map(|w| (w.clone(), "/workspace".to_string()));

    // Even with nothing to mount, the FILE must exist: two services
    // bind-mount ./docker-compose.override.yml, and an absent source makes
    // docker create a DIRECTORY there — after which every compose call
    // that auto-includes the override dies with "is a directory"
    // (defect #17, sandbox rehearsal). Repair the artifact, write a stub.
    if entries.is_empty() && workspace_pair.is_none() {
        ctx.info("No read directories or workspace configured");
        if !ctx.dry_run {
            if ctx.override_file.is_dir() {
                let _ = std::fs::remove_dir_all(&ctx.override_file);
                ctx.warn("docker-compose.override.yml was a DIRECTORY (bind-mount artifact) — removed");
            }
            if !ctx.override_file.exists() {
                let _ = std::fs::write(
                    &ctx.override_file,
                    "# Auto-generated by noo onboard — user directory mounts (none configured)\nservices: {}\n",
                );
            }
        }
        return;
    }

    // One override write with BOTH read dirs (:ro) and the workspace (:rw).
    generate_compose_override(ctx, &entries, workspace_pair.clone());
    if !entries.is_empty() {
        yamlcfg::update_yaml_user_dirs(ctx, &entries);
        ctx.state.user_dir_count = entries.len();
        ctx.success(&format!("{} read directories configured", entries.len()));
    }
    if let Some((h, m)) = &workspace_pair {
        yamlcfg::update_yaml_workspace(ctx, h, m);
        ctx.success(&format!("Workspace: {h} -> {m} (read-write)"));
    }
}

/// Regenerate docker-compose.override.yml with the gateway volume mounts.
/// `workspace` (rw) is appended when present. Read dirs are always :ro.
/// Parity with `helpers._generate_compose_override` (+ workspace append).
fn generate_compose_override(ctx: &Ctx, read_entries: &[(String, String)], workspace: Option<(String, String)>) {
    // Merge with any existing workspace already recorded in the override if we
    // are only writing read dirs, and vice-versa — but keep it simple: build
    // the file from the provided read_entries + workspace argument.
    let mut sorted = read_entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut mounts: Vec<String> = sorted
        .iter()
        .map(|(h, m)| format!("      - {h}:{m}:ro"))
        .collect();
    if let Some((h, m)) = &workspace {
        mounts.push(format!("      - {h}:{m}:rw"));
    }
    // Both services: trellion runs the file executor
    // worker pool out of the gateway — a gateway-only mount left /workspace
    // nonexistent where writes actually happen, live 2026-08-09); the
    // gateway keeps the mounts for ingest/scan paths. The launcher
    // regenerates this file from noomesh.yaml on every start, so this
    // shape only has to be right for the first boot after onboard.
    let mut lines = vec![
        "# Auto-generated by noo onboard — user directory mounts".to_string(),
        "services:".to_string(),
    ];
    for svc in ["gateway", "trellion"] {
        lines.push(format!("  {svc}:"));
        lines.push("    volumes:".to_string());
        lines.extend(mounts.iter().cloned());
    }
    lines.push(String::new());
    let body = lines.join("\n");
    if ctx.dry_run {
        ctx.dry(&format!("write {}", ctx.override_file.display()));
    } else {
        if ctx.override_file.is_dir() {
            // docker bind-mount artifact (see the stub path above).
            let _ = std::fs::remove_dir_all(&ctx.override_file);
        }
        let _ = std::fs::write(&ctx.override_file, body);
    }
}

// ── Dist digest lock ─────────────────────────────────────────────────────

/// The stack tag the dist launcher will start, resolved in the launcher's
/// own order (`noomesh-start.sh --dist`): the process `NOO_IMAGE_TAG`, then
/// `.env`, then the newest `stack-v*` git tag of the checkout.
fn dist_launch_tag(ctx: &Ctx) -> String {
    if let Ok(t) = std::env::var("NOO_IMAGE_TAG") {
        if !t.trim().is_empty() {
            return t.trim().to_string();
        }
    }
    let t = ctx.read_env("NOO_IMAGE_TAG");
    if !t.trim().is_empty() {
        return t.trim().to_string();
    }
    Command::new("bash")
        .arg("-c")
        .arg("git tag -l 'stack-v*' 2>/dev/null | sort -V | tail -1")
        .current_dir(&ctx.repo_root)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().trim_start_matches("stack-").to_string())
        .unwrap_or_default()
}

/// Fetch + verify `stack-<tag>.lock` with the same code `noo upgrade
/// --stack` runs ([`crate::commands::upgrade::stack_lock_with`]) and write it
/// atomically as `<root>/stack.lock`. A release with no lock, or one that
/// does not verify, is an error: a dist install never runs unpinned.
/// Returns the number of image rows pinned.
pub(crate) fn install_dist_stack_lock(
    root: &Path,
    tag: &str,
    fetch: &mut crate::commands::upgrade::ReleaseFileFetch<'_>,
    verify: &crate::commands::upgrade::SigVerify<'_>,
) -> Result<usize, String> {
    use crate::commands::upgrade::{stack_lock_with, write_stack_lock_file};
    let text = match stack_lock_with(tag, fetch, verify) {
        Ok(Some(text)) => text,
        Ok(None) => return Err(format!(
            "stack-{tag} publishes no signed digest lock (stack-{tag}.lock) — a released-image install never runs unpinned"
        )),
        Err((_, msg, _)) => return Err(msg),
    };
    write_stack_lock_file(root, tag, &text)
        .map_err(|e| format!("could not write {}: {e}", root.join("stack.lock").display()))
}

/// The services step's dist gate: true when the verified lock for the
/// launch tag is in place (or this is a dry run), false after recording a
/// hard failure — the caller then starts nothing.
fn pin_dist_stack_lock(ctx: &mut Ctx) -> bool {
    let tag = dist_launch_tag(ctx);
    if tag.is_empty() {
        ctx.error("No release tag to start — NOO_IMAGE_TAG is unset and the checkout has no stack-v* tag");
        ctx.state.hard_failures.push(
            "services: no release tag to pin (set NOO_IMAGE_TAG in .env, then `noo onboard --only services`)".into(),
        );
        return false;
    }
    if ctx.dry_run {
        ctx.dry(&format!("fetch + verify stack-{tag}.lock, write stack.lock"));
        return true;
    }
    ctx.progress(&format!("Verifying the signed digest lock for stack-{tag}..."));
    let g = ctx.g;
    let fetched = install_dist_stack_lock(
        &ctx.repo_root,
        &tag,
        &mut |rel, name| crate::commands::upgrade::fetch_tag_file(g, rel, name),
        &crate::release_sig::verify,
    );
    match fetched {
        Ok(n) => {
            ctx.success(&format!("Digest lock verified: {n} image(s) pinned from stack-{tag} (release-signed)"));
            true
        }
        Err(why) => {
            ctx.error(&format!("Digest lock for stack-{tag} not verified: {why}"));
            ctx.state.hard_failures.push(format!(
                "services: refused to start {tag} without its verified stack lock ({why}); fix the cause, then `noo onboard --only services`"
            ));
            false
        }
    }
}

// ── Step 5: Services ─────────────────────────────────────────────────────

pub fn services(ctx: &mut Ctx) {
    if ctx.state.mode == "worker" {
        ctx.info("Worker mode — core services run on the controller. Skipping.");
        return;
    }
    ensure_storage_dirs(ctx);

    // The host executor. Until 2026-09-24 this offered the bash watcher —
    // hostd's predecessor, with three of its thirteen ops — and nothing in
    // the wizard installed hostd in either mode, so every controller ended
    // `cluster verify` on a red hostd row and could not run a harness
    // Controller mode goes here; worker mode follows the
    // self-agent, further down.
    ensure_hostd_controller(ctx);

    // The sandbox's AppArmor profile, before anything starts the stack: on
    // an AppArmor host Docker's default profile stops Bubblewrap and the
    // sandbox refuses every call (i263b).
    super::sandbox_apparmor::ensure(ctx);

    // ── --from-archive: restore the carried database FIRST ──────────────
    // Ordering is the whole trick (learned live, 2026-09-01): the dump
    // carries schema + migration stamps, so it must land in an EMPTY
    // database BEFORE the gateway's migrations run — and the dump is
    // database-level, so the cluster-global roles must exist first. Bring
    // up postgres alone, ensure roles from the (restored) store, psql the
    // dump in, mark done; the normal full start below then boots onto the
    // restored world and its provisioning passes re-assert grants.
    if let Some(dump) = ctx.state.restore_db.clone() {
        let marker = ctx.repo_root.join(".noo-restore-done");
        if marker.exists() {
            ctx.info("Archive database already restored (marker present).");
        } else if ctx.dry_run {
            ctx.dry("restore the archive database into a fresh postgres");
        } else {
            ctx.progress("Starting postgres alone for the archive restore...");
            let code = sh::run_compose_streamed(ctx, &["up", "-d", "--no-build", "postgres"]);
            if code != 0 || !sh::wait_for_health_docker(ctx, "noo-postgres", 60) {
                ctx.error("postgres did not come up — cannot restore the archive database");
                return;
            }
            ctx.progress("Ensuring cluster-global roles from the secret store...");
            let roles = format!(
                r#"set -e; cd '{home}'
source scripts/lib-secrets.sh >/dev/null 2>&1 && load_secrets >/dev/null 2>&1 || true
ensure() {{
  role="$1"; pw="$2"; [ -z "$pw" ] && return 0
  ex=$(docker exec noo-postgres psql -U noo -d postgres -tAc "select 1 from pg_roles where rolname='$role'" || true)
  if [ "$ex" != "1" ]; then
    esc=$(printf %s "$pw" | sed "s/'/''/g")
    docker exec noo-postgres psql -q -U noo -d postgres -c "CREATE ROLE $role LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '$esc'" >/dev/null
  fi
}}
ensure noo_app "${{NOO_APP_DB_PASSWORD:-}}"
ensure noo_trellion "${{NOO_TRELLION_DB_PASSWORD:-}}"
ensure noo_trellion_ddl "${{NOO_TRELLION_DDL_PASSWORD:-}}"
ensure noo_evolve "${{NOO_EVOLVE_DB_PASSWORD:-}}"
ensure noo_evolve_ddl "${{NOO_EVOLVE_DDL_PASSWORD:-}}"
"#,
                home = ctx.repo_root.display(),
            );
            let _ = Command::new("bash").arg("-c").arg(&roles).status();
            ctx.progress("Restoring the archive database...");
            let restored = Command::new("bash")
                .arg("-c")
                .arg(format!(
                    "set -o pipefail; gunzip -c '{}' | docker exec -i noo-postgres psql -q -U noo -d noomesh",
                    dump.display()
                ))
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if restored {
                let _ = std::fs::write(&marker, "restored
");
                ctx.success("Archive database restored — the stack boots onto the carried world.");
            } else {
                ctx.error("Database restore FAILED — fix and re-run (the wizard resumes; the archive is untouched)");
                return;
            }
        }
    }

    let core_running = sh::are_services_running(&["noo-postgres", "noo-redis", "noo-nats", "noo-node-agent"]);
    let gateway_running = sh::are_services_running(&["noo-gateway"]);
    let some_running = !core_running && sh::are_services_running(&["noo-postgres"]);

    // The gateway serves HTTPS only and REFUSES to start without its TLS
    // material (gateway-rust/src/main.rs, `tls::require_server_material`).
    // Until 2026-09-29 this step probed `http://` when NOO_TLS_CERT was
    // empty and the gateway obliged with a plaintext listener and a warn
    // nobody read. Now a missing leaf is explained here, before the stack
    // is started into a restart loop, and the remedy is the enrollment step.
    // A dry run never wrote the enrollment keys, so it states the
    // requirement instead of stopping on it.
    if ctx.read_env("NOO_TLS_CERT").is_empty() && ctx.dry_run {
        ctx.dry("require NOO_TLS_CERT/NOO_TLS_KEY/NOO_TLS_CA in .env (the enrollment step writes them; the gateway refuses to start without them)");
    } else if ctx.read_env("NOO_TLS_CERT").is_empty() {
        ctx.error(
            "No TLS material in .env (NOO_TLS_CERT is empty) — the gateway serves HTTPS only and \
             refuses to start without it (there is no plaintext listener). Run the enrollment step \
             first: noo onboard --only enrollment (it mints the cluster CA and the gateway leaf, \
             and writes NOO_TLS_CERT/NOO_TLS_KEY/NOO_TLS_CA), then re-run: noo onboard --only services",
        );
        return;
    }
    let health_url = "https://localhost:8080/health".to_string();

    if core_running && gateway_running {
        if sh::http_get_ok(&health_url) {
            ctx.success("All services already running and healthy");
            ctx.state.services_started = true;
            services_tail(ctx);
            return;
        }
        ctx.warn("Gateway running but not responding — credentials may be stale");
    } else if some_running || gateway_running {
        ctx.warn("Partial services detected — will recreate for credential consistency");
    }
    // Recreate whenever ANY services already exist, so current credentials
    // apply cluster-wide. The old expression —
    // `(core_running && gateway_running) || some_running || gateway_running` —
    // collapsed by absorption to `gateway_running || some_running`, silently
    // dropping `core_running`: a core-up/gateway-down state would skip the
    // restart even though those containers hold stale credentials.
    let needs_restart = core_running || gateway_running || some_running;

    // The compose file tags builds as `${NOO_IMAGE_PREFIX:-noomesh}/
    // <svc>:${NOO_IMAGE_TAG:-latest}` — the SLASH form. The old probes only
    // tried the legacy project-name forms (pai-assistant-gateway /
    // _gateway), so custom_images was false even with both images present
    // and every onboard rebuilt from scratch — the first sandbox rehearsal
    // died on exactly that (need_build → dhi.io pulls with no auth).
    //
    // EVERY historical form stays. The default namespace became `noomesh`
    // with the monorepo, and an install that predates it has its images
    // tagged `pai-assistant/<svc>:latest` — dropping that form would make
    // this probe answer "no custom images" on a machine that has them, i.e.
    // reproduce the exact rebuild-from-scratch bug the paragraph above
    // describes, on every existing developer install at once. A stale name
    // in a probe costs nothing; a missing one costs a full rebuild.
    let prefix = std::env::var("NOO_IMAGE_PREFIX").unwrap_or_else(|_| "noomesh".into());
    let tag = std::env::var("NOO_IMAGE_TAG").unwrap_or_else(|_| "latest".into());
    let img_exists = |svc: &str| {
        sh::docker_image_exists(&format!("{prefix}/{svc}:{tag}"))
            || sh::docker_image_exists(&format!("noomesh/{svc}:{tag}"))
            || sh::docker_image_exists(&format!("pai-assistant/{svc}:{tag}"))
            || sh::docker_image_exists(&format!("pai-assistant-{svc}"))
            || sh::docker_image_exists(&format!("pai-assistant_{svc}"))
    };
    let custom_images = img_exists("gateway") && img_exists("node-agent");

    // ── Install mode (onboard audit item 6) ──────────────────────────────
    // dist = released GHCR images (pull-only), dev = build from source.
    // Asked ONCE and persisted as the NOO_INSTALL_MODE bootstrap flag, which
    // is what a bare `noo stack start` honours from then on. Default: a
    // previously persisted answer wins; otherwise dist. It used to fall to
    // dev when no ghcr.io login existed, which put every stranger — the one
    // person guaranteed to have no login — on the path that builds from a
    // private sibling repo and dhi.io base images they cannot reach
    // Dist without a login is
    // handled just below, where the login is offered.
    let persisted_mode = ctx.read_env("NOO_INSTALL_MODE");
    let default_mode = if !persisted_mode.is_empty() { persisted_mode } else { "dist".to_string() };
    let install_mode = loop {
        let ans = ctx
            .asker
            .ask(
                &Prompt::new("Run released images (dist, recommended) or build from source (dev)?")
                    .default(default_mode.clone()),
            )
            .trim()
            .to_ascii_lowercase();
        if ans == "dist" || ans == "dev" {
            break ans;
        }
        // Non-interactive takes the (always-valid) default above, so this
        // loop can only be reached with a real answer to correct.
        ctx.info("please answer 'dist' or 'dev'");
    };
    ctx.update_env("NOO_INSTALL_MODE", &install_mode);
    // Third-party base images (loki/redis/prometheus/...) resolve through
    // ${NOO_BASE_REGISTRY:-ghcr.io/noomesh/dhi}, and dhi.io retires tags — the ghcr
    // mirror exists precisely because those refs "actually fail"
    // (mirror-images.yml). The standalone flow already seeds this; the
    // dist rehearsal showed a plain `onboard --ci` install dies on the
    // first retired tag without it.
    if ctx.read_env("NOO_BASE_REGISTRY").trim().is_empty() {
        // The public DHI mirrors (registry.rs PUBLIC_BASE_REGISTRY), never
        // the upstream-image mirrors at the bare namespace: those run as
        // other uids and cannot read the keys handed to the DHI ones.
        ctx.update_env("NOO_BASE_REGISTRY", crate::registry::PUBLIC_BASE_REGISTRY);
    }
    ctx.state.install_mode = install_mode.clone();

    // ── ghcr.io login: NOT a prerequisite for the core stack ──────────────
    // The core images are PUBLIC at ghcr.io/noomesh, so a standard dist install
    // pulls anonymously and this wizard no longer asks a stranger for a GitHub
    // PAT (it used to: the packages were org-private, and the PAT hunt was the
    // one manual step every fresh install tripped on). Licensed add-ons
    // (trellion-intel, evolve) are separate PRIVATE packages: GHCR access is
    // granted with the entitlement, and `docker login ghcr.io` is needed only
    // then. A missing login is informational here, never a prompt or a failure;
    // a pull that is actually denied surfaces from compose with its own error.
    if install_mode == "dist" && !sh::ghcr_logged_in() {
        ctx.info("ghcr.io: no login needed — the core images are public.");
        ctx.info("Licensed add-ons (trellion-intel, evolve) need GHCR access granted with the \
                  entitlement; `docker login ghcr.io` then.");
    }

    // ── Trellion add-on ───────────────────────
    // The knowledge subsystem is opt-OUT: default yes keeps today's
    // shape. Declining writes NOO_TRELLION_ENABLED=0 — the launcher then
    // starts the slim noo-worker instead of the ML container, and the
    // gateway's degradation contract answers knowledge surfaces with an
    // explicit 503 rather than timeouts. Non-interactive/--ci keeps the
    // default (enabled); `--skip-trellion` pre-answers no.
    // Trellion Basic (the free knowledge pack) is part of the core stack:
    // on unless `--skip-trellion`. The switch itself, and every other
    // add-on — Intelligent tier, evolve, voice — is asked in the final
    // "Add-ons" step, so the paid tiers never read as part of the free
    // install. A first run here therefore starts trellion on; the add-ons
    // step can turn it off and re-apply.
    // The switch is `addons.trellion` in noomesh.yaml — never an .env flag.
    // This step wrote NOO_TRELLION_ENABLED=1 here until 2026-09-07, and the
    // launcher REFUSES to start while any retired add-on flag is in .env, so
    // every fresh walk failed its own service step. Delete any that a seed
    // or an older run left, then launch.
    if ctx.skip.trellion {
        crate::onboard::yamlcfg::update_yaml_addon(ctx, "trellion", false);
        ctx.warn("Trellion disabled (--skip-trellion) — knowledge features answer 503 by design;");
        ctx.warn("re-enable in the Add-ons step: noo onboard --only addons");
    }
    if !ctx.dry_run {
        for flag in ["NOO_TRELLION_ENABLED", "NOO_PRO_ENABLED", "NOO_TRELLION_INTEL_ENABLED", "NOO_VOICE_ENABLED"] {
            match crate::onboard::env::remove_env_key(&ctx.env_path, flag) {
                Ok(true) => ctx.info(&format!("{flag} removed from .env (retired — add-ons live in noomesh.yaml)")),
                Ok(false) => {}
                Err(e) => ctx.warn(&format!("could not remove {flag} from .env: {e}")),
            }
        }
    }

    // What's about to run, in plain language — a fresh operator sees ~15
    // containers appear and should know what each is FOR (finding #20).
    ctx.info("What launches (one stack, all on this machine):");
    ctx.raw("      gateway     — the brain: API + dashboard + agent runtime (what you talk to)");
    ctx.raw("      trellion    — long-term memory: knowledge graph + retrieval");
    ctx.raw("      worker      — background jobs (ingest, summarize, scheduled tasks)");
    ctx.raw("      postgres    — the database (conversations, cluster state, vectors)");
    ctx.raw("      nats        — internal message bus the services talk over");
    ctx.raw("      redis       — fast cache/queues");
    ctx.raw("      ollama-embed— local embedding model (turns text into vectors)");
    ctx.raw("      sandbox     — isolated exec box for agent-run code");
    ctx.raw("      model-cache + volumes — model files and data that survive restarts");

    if install_mode == "dist" {
        // The wizard does NOT build or compose-up here: the whole launch is
        // delegated to the launcher script so the dist logic (release-tag
        // resolution, ghcr login check, dist compose overlay) lives in one
        // place — the same path the sandbox `rehearse --dist` flow exercises
        // from a fresh onboard.
        if !ctx.non_interactive {
            let label = if needs_restart {
                "Restart services from released images now?"
            } else {
                "Start services from released images now? (pulls on first run)"
            };
            if !ctx.asker.confirm(label, true) {
                ctx.info("Skipped. Run 'noo stack start' later.");
                return;
            }
        }
        // A dist install never runs unpinned: the signed digest lock for the
        // tag the launcher will start is fetched, verified and written
        // BEFORE anything starts — the way `noo upgrade --stack` does it.
        // Without it the stack came up by tag, and every later check
        // against the lock (add-on entitlement, image staging) refused with
        // "no verified stack.lock" until an upgrade to the SAME tag (rc.3).
        // Storage first: a missing bind source refuses the launch AFTER the
        // whole image set is pulled, and pulling again cannot create it.
        if let Some((n, root, why)) = storage_preflight_refusal(ctx) {
            ctx.error(&format!("Stack not started: {why}"));
            record_storage_summary_failure(ctx, n, &root);
            return;
        }
        if !pin_dist_stack_lock(ctx) {
            return;
        }
        ctx.progress("Starting stack from released images (scripts/noomesh-start.sh --dist)...");
        // Standalone runs the `standalone` profile instead of the full
        // `controller` one: the same set minus the containerised agent
        // plus ollama-embed — the monitoring set included (it was an
        // opt-in `--profile monitoring` here until 2026-09-28, and the
        // opt-in did not survive the first `noo upgrade --stack`).
        // --core-only: the add-ons step has not run yet, so bring up the base
        // stack and nothing else. Without it a fresh install pulls trellion
        // (~4.5 GB, opt-out so on by default) four steps before it asks
        // whether you want it — and stops it again if you say no.
        let mut script_args: Vec<&str> = vec!["--dist", "--core-only"];
        if std::env::var("NOO_STANDALONE").as_deref() == Ok("1") {
            script_args.push("--profile");
            script_args.push("standalone");
        }
        let mut code = sh::run_script_streamed(ctx, "noomesh-start.sh", &script_args);
        if code != 0 {
            // Fix-and-retry IN PLACE (2026-09-01: a stale-volume failure
            // here cascaded "skipped" through the model step, the self-
            // agent, and the embedder — leaving a scavenger hunt where a
            // wizard should be). One automatic repair pass: sweep device-
            // stale volumes + leftover created-but-dead containers, retry
            // once, and only then fail the step.
            // A preflight refusal (a missing storage directory) is the host's
            // to fix: a volume sweep cannot create a directory, and the
            // retry would pull everything again to be refused the same way.
            if let Some((_, _, why)) = storage_preflight_refusal(ctx) {
                ctx.error(&format!("Stack launch refused: {why}; no repair retry"));
                ctx.state.hard_failures.push(format!("services: the stack was not started ({why})"));
                return;
            }
            ctx.warn("Stack launch failed — attempting automatic repair (stale volume sweep) and ONE retry...");
            if !ctx.dry_run {
                let _ = Command::new("bash").arg("-c")
                    .arg("docker ps -aq --filter name=noo- --filter status=created | xargs -r docker rm -f")
                    .status();
                fix_volume_mismatches(ctx);
            }
            code = sh::run_script_streamed(ctx, "noomesh-start.sh", &script_args);
        }
        if code != 0 {
            ctx.error("Failed to start services from released images (after one repair retry)");
            ctx.state.hard_failures.push("services: the stack did not start from released images (see the launcher output above)".into());
            return;
        }
        ctx.progress("Waiting for gateway on :8080...");
        if sh::wait_for_http(ctx, &health_url, 45) {
            ctx.success("Gateway responding on :8080");
            ensure_cli_login(ctx);
        } else {
            ctx.warn("Gateway not yet responding (may still be starting)");
        }
        ctx.state.services_started = true;

        services_tail(ctx);
        return;
    }

    // Confirm (interactive)
    if !ctx.non_interactive {
        let start_now = if needs_restart {
            ctx.asker.confirm("Restart services to apply current credentials?", true)
        } else if custom_images {
            ctx.asker.confirm("Start core services now?", true)
        } else {
            ctx.asker.confirm("Build and start core services? (first run, may take minutes)", true)
        };
        if !start_now {
            ctx.info("Skipped. Run 'noo stack start' later.");
            return;
        }
    }

    let need_build = !custom_images;

    // The compose file declares noo-cluster as EXTERNAL (workers have
    // pre-compose networks that must not be recreated), so somebody has to
    // create it — and on the controller nobody did: every existing host
    // inherited it from history, and a fresh machine could never `up`
    // ("network noo-cluster declared as external, but could not be found";
    // sandbox rehearsal, defect #13). Idempotent.
    if !ctx.dry_run {
        let _ = Command::new("docker")
            .args(["network", "create", "noo-cluster", "--driver", "bridge"])
            .output();
    }

    // A NOO_DATA_ROOT change leaves bind-backed volumes recorded with the
    // OLD device — compose then fails or silently keeps writing to the old
    // path. Drop the mismatches before any `up`.
    if !ctx.dry_run {
        fix_volume_mismatches(ctx);
    }

    if needs_restart {
        ctx.progress("Syncing database passwords...");
        let synced = sh::sync_db_passwords(ctx, &ctx.read_env("POSTGRES_PASSWORD"), &ctx.read_env("REDIS_PASSWORD"));
        if !synced.is_empty() {
            ctx.success(&format!("Updated passwords in: {}", synced.join(", ")));
        }
        ctx.progress("Restarting all services with current credentials...");
        // Every consumer of the credentials just written, not a fixed six.
        // `compose up --force-recreate` skips a service whose profile it was
        // not given AND one its argument list does not name, so an enabled
        // add-on would keep the OLD passwords — silently, the way
        // an add-on once kept an old NOO_CONTROLLER_SECRET for four days
        // `recreate_args` reads the same add-on declaration
        // the launchers do.
        //
        // And not a fixed six either: the list used to be `postgres, redis,
        // nats, node-agent, trellion, gateway`, so the monitoring set
        // (loki, prometheus, grafana, …) — in the profile, never
        // named — was never started by this step. The set is what the
        // profile PROJECTS, read from compose (2026-09-28).
        let Some(core) = controller_services(ctx) else { return };
        let core_refs: Vec<&str> = core.iter().map(String::as_str).collect();
        // Enabled licensed add-ons run only their verified pins (the
        // launcher's rule). One that is on but unpinned is named here with
        // its remedy, before compose would fail on the unpinned sentinel.
        if !ctx.dry_run {
            if let Err(refused) = sh::addon_pin_env(ctx) {
                for (who, why, fix) in &refused {
                    ctx.error(&format!("{who}: {why} — run: {fix}"));
                }
                let (who, _, fix) = &refused[0];
                ctx.state.hard_failures.push(format!(
                    "services: the {who} add-on is on and has no verified pin to run (run `{fix}`, then `noo onboard --only services`)"
                ));
                return;
            }
        }
        let args = sh::recreate_args(ctx, &core_refs);
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let code = sh::run_compose_streamed(ctx, &argv);
        if code != 0 {
            ctx.error("Failed to restart services");
            ctx.state.hard_failures.push("services: the stack did not restart (see the compose output above)".into());
            return;
        }
        ctx.progress("Waiting for PostgreSQL...");
        sh::wait_for_health_docker(ctx, "noo-postgres", 30);
    } else {
        if need_build {
            ctx.progress("Pulling base images...");
            sh::run_compose_streamed(ctx, &["--profile", "controller", "pull", "--ignore-buildable"]);
            // postgres is source-built too (pai-assistant/postgres-pgvector)
            // — the `up`s below pass --no-build (the compose file's
            // pull_policy: build would otherwise force a rebuild on EVERY
            // up), so anything source-built must be covered here.
            ctx.progress("Building custom images (gateway, node-agent, postgres)...");
            let bcode =
                sh::run_compose_streamed(ctx, &["--profile", "controller", "build", "gateway", "node-agent", "postgres"]);
            if bcode != 0 {
                // A dev install runs what it builds; with no image there is
                // nothing to `up`, and "continuing" used to hand the failure
                // to the next step as a missing-image error nobody could read.
                ctx.error("Image build FAILED — nothing to run. Fix the build, or answer 'dist' to run released images: noo onboard --only services");
                return;
            } else {
                ctx.success("Images built");
            }
        }
        if !core_running {
            // trellion is MANDATORY since an earlier release (worker pool + memory
            // alembic env live there) — without it the trellion migrations never
            // run, four of the six baseline tables never exist, and the gateway
            // fail-closes preflight in a crash-loop (sandbox rehearsal, defect #16).
            ctx.progress("Starting postgres, redis, nats, node-agent, trellion...");
            let (code, out) = sh::run_compose(
                ctx,
                &["--profile", "controller", "up", "-d", "--no-build", "--force-recreate", "postgres", "redis", "nats", "node-agent", "trellion"],
            );
            if code != 0 {
                ctx.error(&format!("Failed to start core services: {}", out.chars().take(300).collect::<String>()));
                ctx.state.hard_failures.push("services: the core services did not start (see the compose output above)".into());
                return;
            }
            ctx.success("Core services started");
            ctx.progress("Waiting for PostgreSQL health check...");
            if sh::wait_for_health_docker(ctx, "noo-postgres", 30) {
                ctx.success("PostgreSQL healthy");
            } else {
                ctx.warn("PostgreSQL not yet healthy (continuing)");
            }
        }
        if !gateway_running {
            ctx.progress("Starting gateway...");
            let (code, out) = sh::run_compose(ctx, &["--profile", "controller", "up", "-d", "--no-build", "--force-recreate", "gateway"]);
            if code != 0 {
                ctx.error(&format!("Failed to start gateway: {}", out.chars().take(300).collect::<String>()));
                return;
            }
            ctx.success("Gateway started");
        }
        // The REST of the profile — worker, sandbox, model-cache and the
        // monitoring set. Two named `up`s above put the database and the
        // gateway first for the health waits; this one brings up everything
        // the profile projects that is not running yet (no --force-recreate:
        // the services just started stay as they are).
        let Some(core) = controller_services(ctx) else { return };
        let rest: Vec<&str> = core
            .iter()
            .map(String::as_str)
            .filter(|s| !["postgres", "redis", "nats", "trellion", "gateway"].contains(s))
            .collect();
        if !rest.is_empty() {
            ctx.progress(&format!("Starting the rest of the controller profile ({})...", rest.join(", ")));
            let mut argv: Vec<&str> = vec!["--profile", "controller", "up", "-d", "--no-build"];
            argv.extend(rest.iter().copied());
            let (code, out) = sh::run_compose(ctx, &argv);
            if code != 0 {
                ctx.error(&format!("Failed to start the rest of the profile: {}", out.chars().take(300).collect::<String>()));
                ctx.state.hard_failures.push("services: the monitoring set and supporting services did not start (see the compose output above)".into());
                return;
            }
            ctx.success("Controller profile running");
        }
    }

    ctx.progress("Waiting for gateway on :8080...");
    if sh::wait_for_http(ctx, &health_url, 45) {
        ctx.success("Gateway responding on :8080");
        ensure_cli_login(ctx);
    } else {
        ctx.warn("Gateway not yet responding (may still be starting)");
    }

    ctx.state.services_started = true;
    services_tail(ctx);
}

/// THE one services ending — every branch of `services()` (already-healthy,
/// restart-for-credentials, dist launch, source build) finishes here, so a
/// duty added to the tail exists on every path. Three divergent copies are
/// how the embedder-ensure ran on exactly one of them and both live walks
/// silently skipped it (2026-09-01).
fn services_tail(ctx: &mut Ctx) {
    ensure_self_agent(ctx);
    ensure_hostd_worker(ctx);
    ensure_llm_placement(ctx);
    ensure_embed_model(ctx);
    ensure_scale_out_hint(ctx);
    reset_grafana_password(ctx);
    show_service_status(ctx);
}

/// The controller's own node agent (finding #15; i67), idempotent. Runs for
/// any controller that runs (or, standalone, should run) a host agent —
/// standalone or source checkout, interactive or `--ci` — and always says
/// why when it does nothing, because `noo onboard --only services` is the
/// remedy the rail prints for a controller without its node identity.
///
/// The only sudo is creating the node identity (the first install, or once
/// for a controller installed before i67); everything else rides the rail.
fn ensure_self_agent(ctx: &mut Ctx) {
    if ctx.dry_run {
        // The first install uses sudo — the one thing a dry run must never do.
        ctx.dry("install the host node agent (first install, sudo once) or restage it over the rail");
        return;
    }
    let systemctl_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "noo-node-agent"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let node_id = {
        let n = ctx.read_env("NODE_ID");
        if n.is_empty() { "controller".to_string() } else { n }
    };
    let identity_ok = crate::commands::provision::pull_units_missing(&node_id).is_empty();
    let interactive = !ctx.non_interactive && ctx.ui.inherit_stdio() && super::prompt::stdin_is_tty();
    let sudo_quiet = sudo_cmd(false).args(["true"])
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false);
    let controller = crate::role::detect().controller;
    use crate::commands::provision::{self_agent_step, SelfAgentStep};
    match self_agent_step(controller.as_ref(),
        std::path::Path::new("/usr/local/bin/noo-node-agent").is_file(),
        systemctl_active, identity_ok, interactive, sudo_quiet)
    {
        SelfAgentStep::Skip(why) => ctx.info(&format!("Self-agent: skipped — {why}.")),
        SelfAgentStep::AlreadyOnRail => ctx.info("Self-agent already running (noo-node-agent); upgrades reach it over the rail."),
        SelfAgentStep::Rail => {
            ctx.info(&format!("Restaging the self-agent for '{node_id}' over the rail{}.",
                if identity_ok { " (no sudo)" } else { " — its node identity is created first, sudo once" }));
            hydrate_process_env(ctx);
            // In a child process: `cluster provision` reports failures by
            // exiting, and that must not end onboard here.
            match crate::commands::upgrade::provision_one(ctx.g, &node_id, &[]) {
                Ok(0) => {}
                _ => ctx.warn(&format!("Self-agent restage did not complete — onboard continues; retry: noo cluster provision {node_id}")),
            }
        }
        SelfAgentStep::FirstInstall => {
            ctx.info("This controller also needs its own node agent (a host process —");
            ctx.info("containers can't run it) to serve models and appear in the mesh.");
            let go = !interactive || ctx.asker.confirm(
                &format!("Install the host agent and its node identity for '{node_id}' now? (uses sudo, once)"), true);
            if go {
                hydrate_process_env(ctx);
                // An error comes back here (provision_local never exits):
                // warn and go on with hostd, placement, the embed model and
                // the rest of the services step.
                if let Err(e) = crate::commands::provision::provision_local(ctx.g, &node_id, None) {
                    ctx.warn(&format!("Self-agent install did not complete ({e}) — onboard continues; retry later: noo onboard --only services"));
                }
            } else {
                ctx.info("Skipped — install any time: noo onboard --only services");
            }
        }
    }
}

/// Standalone runs chat + embedding in ONE ollama (a multi-model server;
/// a second container is idle overhead on a single box). Say so, and name
/// the growth path — inform, don't ask (operator, 2026-09-01).
fn ensure_scale_out_hint(ctx: &mut Ctx) {
    if std::env::var("NOO_STANDALONE").as_deref() == Ok("1") {
        ctx.info("Chat + embedding share this box's single ollama. When a GPU node joins,");
        ctx.info("`noo cluster place <node> ollama <model>` moves chat inference there.");
    }
}

/// Standalone only: pull the embedder the TLS step configured into the
/// ollama-embed container. A configured model that is not present is how
/// the first standalone controller's RAG stayed silently down (host8,
/// 2026-09-01: trellion 503'd on every embed; nothing anywhere had ever
/// pulled a model into ollama-embed). Best-effort — a failed pull warns
/// with the exact recovery command instead of blocking onboarding.
fn ensure_embed_model(ctx: &mut Ctx) {
    if !ctx.repo_root.join(".noo-standalone").exists() || ctx.dry_run {
        return;
    }
    let model = {
        let m = ctx.read_env("PAGEINDEX_EMBEDDING_MODEL");
        if m.is_empty() { "harrier".to_string() } else { m }
    };
    for line in ensure_embed_model_core(&model) {
        match line.chars().next() {
            Some('+') => ctx.success(&line[1..]),
            Some('!') => ctx.warn(&line[1..]),
            Some('.') => ctx.progress(&line[1..]),
            _ => ctx.raw(&line),
        }
    }
}

/// Where `ollama create` stages a Modelfile and its weight INSIDE the ollama
/// container. The hardened image runs as uid 65532 with a root-owned `/`, so
/// a root-level `/convert` cannot be made (rc.2, 0.6.16); the directory lives
/// in the user's own store (HOME/.ollama, a mounted volume writable in every
/// deployment shape). Beside `models/`, never inside it. The same value is in
/// node-agent-go (`convertDir`) and scripts/noo-model-convert.sh
/// (`OLLAMA_CONVERT_DIR`); tests/test_ollama_convert_dir.py ties them.
pub(crate) const OLLAMA_CONVERT_DIR: &str = "/home/nonroot/.ollama/convert";

/// The shell line that stages harrier into the embed container, creates the
/// model, and removes the staging directory whatever the outcome. Returns the
/// exit status of `ollama create`, not of the cleanup.
pub(crate) fn harrier_create_script(embed: &str, host_dir: &str) -> String {
    let c = OLLAMA_CONVERT_DIR;
    format!(
        "chmod a+r '{host_dir}/harrier-Q4_K_M.gguf' '{host_dir}/harrier.Modelfile'; \
         docker exec {embed} sh -c 'rm -rf {c} && mkdir -p {c}' && \
         docker cp '{host_dir}/harrier-Q4_K_M.gguf' {embed}:{c}/ && \
         docker cp '{host_dir}/harrier.Modelfile' {embed}:{c}/Modelfile && \
         docker exec -w {c} {embed} ollama create harrier -f Modelfile; rc=$?; \
         docker exec {embed} rm -rf {c} >/dev/null 2>&1; exit $rc"
    )
}

/// The harrier artifact image: `<release namespace>/harrier:v1`, published
/// by `.github/workflows/publish-harrier.yml` from the `models-harrier-v1`
/// release. Follows NOO_IMAGE_PREFIX so a mirror or a namespace change
/// moves it with every other image.
pub(crate) fn harrier_artifact_ref() -> String {
    let prefix = crate::commands::provision::release_var("NOO_IMAGE_PREFIX");
    let prefix = if prefix.is_empty() { crate::registry::IMAGE_NAMESPACE.to_string() } else { prefix.trim_end_matches('/').to_string() };
    format!("{prefix}/harrier:v1")
}

/// Ctx-free core, shared with `noo migrate import` (which has no wizard
/// context but the same duty: a configured embedder that is not PRESENT is
/// silent RAG death). Returns display lines tagged +success/!warn/.progress.
pub(crate) fn ensure_embed_model_core(model: &str) -> Vec<String> {
    let mut out_lines = Vec::new();
    let embed = crate::envfile::container("ollama-embed");
    let (probe, out) = sh::docker(&["exec", &embed, "ollama", "list"]);
    if probe == 0 && out.contains(model) {
        return out_lines; // already present
    }
    if model == "harrier" {
        // harrier is locally converted (HF→GGUF→ollama create) — there is
        // nothing to `ollama pull`. The artifact is an OCI image under the
        // release namespace (three files, no runtime): `docker create` +
        // `docker cp` from the registry the stack already logs into. The
        // previous path ran `gh release download`, which a fresh host has
        // no `gh` for — and the release it named stayed behind in the old
        // repo — so every fresh box came up with no embedder (2026-09-07).
        let artifact = harrier_artifact_ref();
        out_lines.push(format!(".Fetching the harrier embedder artifact into {embed} ({artifact})..."));
        let tmp = std::env::temp_dir().join(format!("noo-harrier-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);
        let src = format!("noo-harrier-src-{}", std::process::id());
        let fetched = Command::new("bash").arg("-c")
            .arg(format!(
                "docker rm -f '{src}' >/dev/null 2>&1; \
                 docker pull -q '{artifact}' >/dev/null && \
                 docker create --name '{src}' '{artifact}' >/dev/null && \
                 docker cp '{src}:/harrier/.' '{d}/'; rc=$?; docker rm -f '{src}' >/dev/null 2>&1; exit $rc",
                d = tmp.display()
            ))
            .status().map(|s| s.success()).unwrap_or(false);
        let sha_ok = fetched
            && Command::new("bash").arg("-c")
                .arg(format!("cd '{}' && sha256sum -c harrier.sha256 >/dev/null 2>&1", tmp.display()))
                .status().map(|s| s.success()).unwrap_or(false);
        let created = sha_ok
            && Command::new("bash").arg("-c")
                .arg(harrier_create_script(&embed, &tmp.display().to_string()))
                .status().map(|s| s.success()).unwrap_or(false);
        let _ = std::fs::remove_dir_all(&tmp);
        if created {
            out_lines.push("+Embedding model ready: harrier (1024-dim)".into());
        } else {
            out_lines.push(format!(
                "!Could not fetch/create harrier from {artifact} — RAG embedding stays down. Manual recovery:"));
            out_lines.push(format!("      docker create --name harrier-src {artifact} && docker cp harrier-src:/harrier/. /tmp/harrier/ && docker rm harrier-src"));
            out_lines.push(format!("      docker exec {embed} mkdir -p {OLLAMA_CONVERT_DIR} && docker cp /tmp/harrier/harrier-Q4_K_M.gguf {embed}:{OLLAMA_CONVERT_DIR}/ && docker cp /tmp/harrier/harrier.Modelfile {embed}:{OLLAMA_CONVERT_DIR}/Modelfile"));
            out_lines.push(format!("      docker exec -w {OLLAMA_CONVERT_DIR} {embed} ollama create harrier -f Modelfile"));
        }
        return out_lines;
    }
    out_lines.push(format!(".Pulling the embedding model ({model}) into {embed}..."));
    let ok = Command::new("docker").args(["exec", &embed, "ollama", "pull", model])
        .status().map(|s| s.success()).unwrap_or(false);
    if ok {
        out_lines.push(format!("+Embedding model ready: {model}"));
    } else {
        out_lines.push(format!(
            "!Could not pull {model} — RAG embedding stays down until: docker exec {embed} ollama pull {model}"
        ));
    }
    out_lines
}

/// Remove `pai-assistant_*` bind-backed volumes whose recorded device no
/// longer matches the compose-rendered one (stale after a NOO_DATA_ROOT
/// change). Port of Python `step_services._fix_volume_mismatches`, dropped
/// in the original Rust port. Best-effort: any probe failure just returns.
fn fix_volume_mismatches(ctx: &Ctx) {
    let (code, out) = sh::run_compose(ctx, &["--profile", "controller", "config", "--format", "json"]);
    if code != 0 {
        return;
    }
    let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&out) else {
        return;
    };
    // The project name comes from compose itself — the hardcoded
    // "pai-assistant_" here outlived the rename and made this fixer INERT
    // for every noomesh_* volume (2026-09-01: two stale-volume ambushes it
    // was built to prevent).
    let project = cfg
        .get("name")
        .and_then(|n| n.as_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("noomesh")
        .to_string();
    let mut expected: Vec<(String, String)> = Vec::new();
    if let Some(vols) = cfg.get("volumes").and_then(|v| v.as_object()) {
        for (name, vol_cfg) in vols {
            let opts = &vol_cfg["driver_opts"];
            if opts["type"].as_str() == Some("none") {
                if let Some(device) = opts["device"].as_str().filter(|d| !d.is_empty()) {
                    expected.push((format!("{project}_{name}"), device.to_string()));
                }
            }
        }
    }
    if expected.is_empty() {
        return;
    }
    let ls = Command::new("docker")
        .args(["volume", "ls", "--filter", &format!("name={project}_"), "--format", "{{.Name}}"])
        .output();
    let Ok(ls) = ls else { return };
    if !ls.status.success() {
        return;
    }
    let existing = String::from_utf8_lossy(&ls.stdout);
    let mut removed = 0usize;
    for vol in existing.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some((_, want_device)) = expected.iter().find(|(n, _)| n == vol) else {
            continue;
        };
        let device = Command::new("docker")
            .args(["volume", "inspect", vol, "--format", "{{.Options.device}}"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        if device != *want_device {
            let ok = Command::new("docker")
                .args(["volume", "rm", "-f", vol])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                removed += 1;
            }
        }
    }
    if removed > 0 {
        ctx.info(&format!(
            "Removed {removed} stale Docker volume(s) (config doesn't match current NOO_DATA_ROOT)"
        ));
    }
}

/// The launch preflight, over what onboard owns: every storage directory
/// the stack bind-mounts must exist before anything is pulled or started.
/// `Some(text)` = refuse. A missing one is a host problem (Docker would
/// create it root-owned): pulling the image set cannot fix it and neither
/// can the volume-sweep repair, so neither runs (i276). A dry run creates
/// nothing and is never refused.
fn storage_preflight_refusal(ctx: &Ctx) -> Option<(usize, String, String)> {
    if ctx.dry_run {
        return None;
    }
    let root = ctx.read_env("NOO_DATA_ROOT");
    let root = if root.is_empty() { crate::commands::data_root::DEFAULT_DATA_ROOT.to_string() } else { root };
    let missing: Vec<_> = storage_targets(ctx, Path::new(&root)).into_iter().filter(|(_, t)| !t.exists()).collect();
    let first = missing.first()?;
    Some((
        missing.len(),
        root.clone(),
        format!(
            "{}: missing (Docker would create it root-owned) and {} director{} under {root} in all — nothing was pulled or started",
            first.1.display(),
            missing.len(),
            if missing.len() == 1 { "y" } else { "ies" }
        ),
    ))
}

fn ensure_storage_dirs(ctx: &mut Ctx) {
    let root = ctx.read_env("NOO_DATA_ROOT");
    let root = if root.is_empty() { crate::commands::data_root::DEFAULT_DATA_ROOT.to_string() } else { root };
    let path = Path::new(&root);
    let missing: Vec<_> = storage_targets(ctx, path).into_iter().filter(|(_, t)| !t.exists()).collect();
    if !missing.is_empty() {
        ctx.info(&format!("Creating {} missing storage dirs under {}", missing.len(), root));
        create_storage_dirs(ctx, path);
    }
}

// ── noo-hostd on the controller ───────────────────────────
//
// The controller is both roles, and each hostd mode holds only the
// authority its job needs: controller mode is a USER unit (docker, compose,
// backup, rotate) on the spool the gateway bind-mounts; worker mode is a
// SYSTEM unit (root: harness and agent lifecycle) on the node-agent's spool,
// which is where `cluster verify` reads the heartbeat. One combined instance
// would hold root AND docker on the most privileged box in the fleet.

const HOSTD_BIN: &str = "/usr/local/bin/noo-hostd";

/// `noo-hostd install …` for a mode: controller names the install root
/// (its spool lives under it); worker is always a system unit and takes no
/// root. Pure, so the two shapes are pinned.
fn hostd_install_args(mode: &str, root: &str) -> Vec<String> {
    match mode {
        "controller" => vec!["install".into(), "--root".into(), root.to_string(), "--mode".into(), "controller".into()],
        _ => vec!["install".into(), "--mode".into(), "worker".into()],
    }
}

/// The same check noo-apply.sh makes before it swaps a node's hostd.
fn looks_like_elf(bytes: &[u8]) -> bool {
    bytes.len() > 4 && bytes[..4] == [0x7f, b'E', b'L', b'F']
}

/// `/usr/local/bin/noo-hostd`, the path every node uses — obtained the way
/// `noo upgrade` stages it for nodes: this release's asset from the
/// controller's asset cache, else fetched from the release; installed with
/// sudo, root-owned, as noo-apply.sh does. Reused when already present.
fn obtain_hostd_binary(ctx: &mut Ctx) -> Result<std::path::PathBuf, String> {
    let target = std::path::PathBuf::from(HOSTD_BIN);
    if target.is_file() {
        return Ok(target);
    }
    let asset = crate::commands::provision::hostd_asset_for(std::env::consts::OS, std::env::consts::ARCH)
        .ok_or_else(|| format!("no noo-hostd build for {}/{}", std::env::consts::OS, std::env::consts::ARCH))?;
    let cached = crate::commands::provision::cli_asset_cache_dir(&ctx.repo_root).join(&asset);
    let bytes = match std::fs::read(&cached).ok().filter(|b| !b.is_empty()) {
        Some(b) => b,
        None => {
            ctx.progress(&format!("Fetching {asset} from release noo-cli-v{}...", env!("CARGO_PKG_VERSION")));
            let b = crate::commands::upgrade::fetch_release_file(ctx.g, env!("CARGO_PKG_VERSION"), &asset, None)?;
            if let Some(dir) = cached.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(&cached, &b);
            b
        }
    };
    if !looks_like_elf(&bytes) {
        return Err(format!("{asset} is not an ELF executable — refusing to install it"));
    }
    let staged = std::env::temp_dir().join(format!("noo-hostd-{}", std::process::id()));
    std::fs::write(&staged, &bytes).map_err(|e| format!("could not stage the binary: {e}"))?;
    let ok = ctx_sudo(ctx)
        .args(["install", "-m", "755", "-o", "root", "-g", "root"])
        .arg(&staged)
        .arg(&target)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = std::fs::remove_file(&staged);
    if !ok {
        return Err(format!("sudo install to {HOSTD_BIN} failed"));
    }
    Ok(target)
}

/// Two executors on one spool would both claim commands, so the watcher
/// stops BEFORE controller mode starts — the same change, not a later one.
fn stop_watcher(ctx: &mut Ctx) {
    ctx.progress("Stopping the host watcher (noo-hostd takes over its spool)...");
    let _ = Command::new("systemctl").args(["--user", "disable", "--now", "noo-host-watcher.service"]).status();
    let _ = Command::new("pkill").args(["-f", "noo-host-watcher.sh"]).status();
    if watcher_running() {
        ctx.warn("The host watcher is still running — stop it before hostd claims from the same spool: pkill -f noo-host-watcher.sh");
    } else {
        ctx.success("Host watcher stopped and disabled (it is retired; noo-hostd runs host commands)");
    }
}

/// Whether this run may install noo-hostd. The binary goes to
/// /usr/local/bin through sudo, so an interactive run can answer sudo's
/// prompt; a non-interactive one (`--ci`, no terminal) can only when sudo
/// is passwordless, which a cloud image's default user and a CI box have.
/// Before i251 `--ci` always skipped, and on a host with systemd the
/// launcher then refused to create the spool it treats as hostd's, so the
/// documented non-interactive install never started the stack. Pure, so
/// all three answers are pinned.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HostdInstall {
    Interactive,
    PasswordlessSudo,
    Skip,
}

pub(crate) fn hostd_install_decision(interactive: bool, sudo_quiet: bool) -> HostdInstall {
    if interactive {
        HostdInstall::Interactive
    } else if sudo_quiet {
        HostdInstall::PasswordlessSudo
    } else {
        HostdInstall::Skip
    }
}

/// i267: may a sudo in this run ask for a password? Only when a person is
/// at a terminal the wizard does not own. Never in a non-interactive run
/// (`--ci`, scripted): on a CI box there is no one to answer, and in a
/// terminal the prompt simply waits — take 14b of the onboarding film sat at
/// "[sudo] password for you:" for an hour (0.6.12-rc.1; the same gate is in
/// 0.6.10 and 0.6.11). Never under the full-screen UI either: its raw-mode
/// terminal cannot take a password. Pure, so the table is pinned.
pub(crate) fn sudo_may_prompt(non_interactive: bool, inherit_stdio: bool, stdin_tty: bool) -> bool {
    !non_interactive && inherit_stdio && stdin_tty
}

#[cfg(test)]
thread_local! {
    /// A test points every onboard sudo at a fake (`sudo_seam_tests`).
    static SUDO_BIN: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// THE `sudo` of the onboard steps: `sudo -n` with stdin closed unless
/// `may_prompt` ([`sudo_may_prompt`]). Every onboard sudo is built here —
/// pinned by `every_onboard_sudo_goes_through_the_seam` — so a new step
/// cannot reintroduce a prompting call. A caller that pipes stdin (`tee`)
/// sets it after; `-n` still forbids the prompt.
pub(crate) fn sudo_cmd(may_prompt: bool) -> Command {
    #[cfg(test)]
    let prog = SUDO_BIN.with(|b| b.borrow().clone()).unwrap_or_else(|| "sudo".into());
    #[cfg(not(test))]
    let prog = std::path::PathBuf::from("sudo");
    let mut c = Command::new(prog);
    if !may_prompt {
        c.arg("-n").stdin(std::process::Stdio::null());
    }
    c
}

/// [`sudo_may_prompt`] for this run.
pub(crate) fn ctx_sudo_may_prompt(ctx: &Ctx) -> bool {
    sudo_may_prompt(ctx.non_interactive, ctx.ui.inherit_stdio(), super::prompt::stdin_is_tty())
}

/// [`sudo_cmd`] for this run.
pub(crate) fn ctx_sudo(ctx: &Ctx) -> Command {
    sudo_cmd(ctx_sudo_may_prompt(ctx))
}

/// i267: a privileged action a non-interactive run could not take, because
/// sudo needs a password and this run cannot ask. Loud: one plain line now,
/// and a hard failure, so the closing block says "did NOT complete" with it
/// and the run exits 1. An interactive run keeps its warning (the person
/// at the terminal declined or failed the prompt and saw it).
pub(crate) fn sudo_refused(ctx: &mut Ctx, what: &str, cmd: &str) {
    if !ctx.non_interactive {
        return;
    }
    let line = format!("{what}: sudo needs a password and this non-interactive run cannot ask — run: {cmd}");
    ctx.error(&line);
    ctx.state.hard_failures.push(line);
}

/// `sudo -n true`: sudo works here without a prompt (a cloud image's
/// default user, a CI box, the film's box). What a non-interactive run may
/// elevate with: hostd's install (i251), the private-key grants (i266).
pub(crate) fn passwordless_sudo() -> bool {
    sudo_cmd(false)
        .arg("true")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn hostd_can_run_here(ctx: &mut Ctx) -> bool {
    let interactive = !ctx.non_interactive && ctx.ui.inherit_stdio() && super::prompt::stdin_is_tty();
    let sudo_quiet = !interactive && passwordless_sudo();
    match hostd_install_decision(interactive, sudo_quiet) {
        HostdInstall::Interactive => true,
        HostdInstall::PasswordlessSudo => {
            ctx.info("noo-hostd: no terminal, but sudo needs no password here — installing it (controller mode, a user unit)");
            true
        }
        HostdInstall::Skip => {
            ctx.info("noo-hostd not installed here (needs sudo and a terminal). Later: noo onboard --only services");
            false
        }
    }
}

/// Controller mode: a user unit on this install's spool.
fn ensure_hostd_controller(ctx: &mut Ctx) {
    if ctx.dry_run {
        ctx.dry("install noo-hostd (controller mode: a user unit on this install's spool; the watcher stops first)");
        return;
    }
    if !hostd_can_run_here(ctx) {
        return;
    }
    let bin = match obtain_hostd_binary(ctx) {
        Ok(b) => b,
        Err(e) => {
            ctx.warn(&format!("noo-hostd: {e} — backups, rotation and self-heal will queue until it runs. Later: noo onboard --only services"));
            return;
        }
    };
    if watcher_running() {
        stop_watcher(ctx);
    }
    ctx.progress("Installing noo-hostd, controller mode (compose, backup, rotate — a user unit)...");
    let root = ctx.repo_root.to_string_lossy().into_owned();
    let ok = Command::new(&bin).args(hostd_install_args("controller", &root)).status().map(|s| s.success()).unwrap_or(false);
    if ok {
        ctx.success("noo-hostd (controller mode) installed and running");
    } else {
        ctx.warn(&format!("noo-hostd install (controller mode) failed — run: {HOSTD_BIN} install --root {root} --mode controller"));
    }
}

/// Worker mode: a system unit beside the self-agent, whose spool it serves.
/// Without it the agent reports hostd DOWN and cannot start a harness.
fn ensure_hostd_worker(ctx: &mut Ctx) {
    if ctx.dry_run {
        ctx.dry("install noo-hostd (worker mode: a system unit beside the self-agent, uses sudo)");
        return;
    }
    let agent_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "noo-node-agent"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !agent_active {
        ctx.info(&format!("Worker-mode hostd follows the self-agent: noo onboard --only services, then sudo {HOSTD_BIN} install --mode worker"));
        return;
    }
    if !hostd_can_run_here(ctx) {
        return;
    }
    let bin = match obtain_hostd_binary(ctx) {
        Ok(b) => b,
        Err(e) => {
            ctx.warn(&format!("noo-hostd: {e}"));
            return;
        }
    };
    if !ctx.asker.confirm("Install noo-hostd in worker mode too? (system unit, uses sudo — lets this box run a harness)", true) {
        ctx.info(&format!("Skipped — later: sudo {HOSTD_BIN} install --mode worker"));
        return;
    }
    let ok = ctx_sudo(ctx).arg(&bin).args(hostd_install_args("worker", "")).status().map(|s| s.success()).unwrap_or(false);
    if ok {
        ctx.success("noo-hostd (worker mode) installed — the agent's heartbeat will show it within a tick");
    } else {
        ctx.warn(&format!("noo-hostd install (worker mode) failed — run: sudo {HOSTD_BIN} install --mode worker"));
    }
}

fn watcher_running() -> bool {
    Command::new("pgrep")
        .args(["-f", "noo-host-watcher.sh"])
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn show_service_status(ctx: &Ctx) {
    let (code, out) = sh::docker(&["ps", "--filter", "name=noo-", "--format", "{{.Names}}\t{{.Status}}\t{{.Ports}}"]);
    if code != 0 || out.trim().is_empty() {
        return;
    }
    ctx.info("Running services:");
    for line in out.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 2 {
            let ports = parts.get(2).copied().unwrap_or("");
            ctx.info(&format!("  {:<24} {:<30} {ports}", parts[0], parts[1]));
        }
    }
}

/// Declare the controller's vllm placement (tier-1 only) so the node-agent
/// starts it. Best-effort — a failure is a warning. Parity with
/// `_ensure_llm_placement`.
/// Hydrate-OUT (findings #58/#59): the wizard writes config to FILES, but
/// its own in-process command calls (login, the self-agent install) resolve via
/// the PROCESS env — which, on a true fresh box (no .env at CLI startup),
/// is empty: auto-login dialed http:// at an HTTPS gateway, and the
/// self-agent's cert issuance reported "no cluster CA found" two steps
/// after the CA was minted. Push what this run established into the
/// process env before any in-process command needs it.
fn hydrate_process_env(ctx: &Ctx) {
    for key in [
        "NOO_GATEWAY_URL",
        "CONTROLLER_URL",
        "NOO_PKI_DIR",
        "NOO_TLS_CA",
        "NOO_TLS_CERT",
        "NOO_TLS_KEY",
        "NODE_IP",
        // #63 (the #58 family's last member): the self-agent's image
        // extraction reads the pin pair — left out of the first hydrate
        // list, so the freshest run died ONE step further than ever.
        "NOO_IMAGE_PREFIX",
        "NOO_IMAGE_TAG",
        "NOO_BASE_REGISTRY",
        "NOO_INSTALL_MODE",
        // The self-agent's data root (fresh walk 2026-09-07): provision_local
        // read the PROCESS env, found nothing, and wrote /data/noo into the
        // host agent env — every backend the controller placed on itself
        // then failed to bind-mount a directory that did not exist.
        "NOO_DATA_ROOT",
    ] {
        if std::env::var(key).map(|v| v.is_empty()).unwrap_or(true) {
            let v = ctx.read_env(key);
            if !v.is_empty() {
                std::env::set_var(key, v);
            }
        }
    }
    // The URL that VERIFIES: the gateway cert carries the tailnet name +
    // IP as SANs; localhost may not be among them. Prefer the ts.net name.
    if crate::envfile::gateway_url_var_is_blank()
        && !ctx.state.ts_dnsname.is_empty()
    {
        std::env::set_var(
            "NOO_GATEWAY_URL",
            format!("https://{}:{}", ctx.state.ts_dnsname, 8080 + ctx.state.port_offset),
        );
    }
}

/// How long the wizard waits for the admin's login to be accepted after
/// the gateway first answers (finding #101: on a FIRST boot `/health`
/// answers before the migrations and the admin seed finish).
const LOGIN_SEED_WAIT: std::time::Duration = std::time::Duration::from_secs(120);

/// The wizard's own admin login: the credential every operator call after
/// the stack starts carries — the service-key mint, the operator
/// certificate, the hardened posture, the MCP door.
///
/// There is no shared-secret fallback
/// (no break-glass; the same path as end users); the wizard used to sign
/// those calls as `cli-onboard` whenever it held no login. Instead:
///
/// 1. **The password**, when this run has it — it just set it (interactive
///    or `--non-interactive`, which generates one) — or the operator types
///    it on a re-run. The login is retried through the first-boot seed
///    window (finding #101) instead of failing on the race.
/// 2. **A one-time host ticket** otherwise: a `--non-interactive` re-run
///    with no password in hand, an operator who declined to type it, or a
///    password login that never succeeded. The wizard runs on the
///    controller, so it writes the ticket's hash into the gateway's
///    database (`crate::host_access`, the host's own access) and exchanges
///    it once for the admin's ordinary login.
///
/// Either way the CLI ends up holding the admin's login, stored like
/// `noo auth login` stores it.
pub(crate) fn ensure_cli_login(ctx: &mut Ctx) {
    if ctx.dry_run {
        return;
    }
    // A credential from an EARLIER install is stale by construction once this
    // run has set the admin password (new JWT secret, new admin seed): keep
    // it only when this run did not touch the account. Otherwise a reinstall
    // on the same box skipped the login and every later call, including
    // `noo health`, got a 401 with a refresh that also failed (2026-09-27).
    if ctx.state.admin_password.is_empty() && crate::credentials::load().is_some() {
        return; // already holding a per-user credential from this account
    }
    let user = if !ctx.state.admin_username.is_empty() {
        ctx.state.admin_username.clone()
    } else {
        ctx.read_env("NOO_ADMIN_USER")
    };
    let user = if user.is_empty() { "admin".to_string() } else { user };
    hydrate_process_env(ctx);
    let password = if !ctx.state.admin_password.is_empty() {
        Some(ctx.state.admin_password.clone())
    } else if ctx.non_interactive {
        None
    } else if ctx.asker.confirm(
        &format!(
            "Log your CLI in as '{user}' with its password now? (No: the wizard logs in with a \
             one-time host ticket instead)"
        ),
        true,
    ) {
        Some(ctx.asker.ask(&Prompt::new(&format!("Password for {user}")).secret().required()))
    } else {
        None
    };
    let deadline = std::time::Instant::now() + LOGIN_SEED_WAIT;
    if let Some(password) = password {
        ctx.progress(&format!("Logging the CLI in as {user}..."));
        let last_err = loop {
            match crate::commands::auth::login_and_store(ctx.g, &user, &password) {
                Ok(subject) => {
                    ctx.success(&format!("CLI logged in as {subject} — commands are now attributable to you."));
                    return;
                }
                Err(e) if std::time::Instant::now() >= deadline => break e,
                Err(_) => {}
            }
            ctx.progress("login not accepted yet (first-boot seeding?) — retrying…");
            std::thread::sleep(std::time::Duration::from_secs(5));
        };
        ctx.warn(&format!("The password login was not accepted ({last_err}) — trying a one-time host ticket."));
    }
    ctx.progress(&format!("Logging the CLI in as {user} with a one-time host ticket..."));
    let deadline = deadline.max(std::time::Instant::now() + std::time::Duration::from_secs(30));
    let last_err = loop {
        match crate::host_access::login_with_ticket(ctx.g, &user, "onboard") {
            Ok(subject) => {
                ctx.success(&format!(
                    "CLI logged in as {subject} (one-time host ticket) — commands are now attributable to you."
                ));
                return;
            }
            Err(e) if std::time::Instant::now() >= deadline => break e,
            Err(_) => {}
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    };
    ctx.warn(&format!("CLI login failed: {last_err}"));
    ctx.warn(
        "The steps that act as the operator (service keys, the operator certificate, the hardened posture) \
         will say what they skipped — nothing falls back to a shared secret.",
    );
    ctx.info("Fix the login, then re-run them: noo auth login, then noo onboard --only services");
}

fn ensure_llm_placement(ctx: &mut Ctx) {
    let node_id = ctx.read_env("NODE_ID");
    let model = ctx.read_env("VLLM_MODEL");
    let tier = ctx.read_env("NODE_TIER");
    if node_id.is_empty() || model.is_empty() {
        if ctx.repo_root.join(".noo-standalone").exists() {
            ctx.info("Chat is served by this box's single ollama (static fallback) — no placement needed.");
            // Say so in the config too. With --skip-model the model step
            // (the only writer of cluster.default_backend) never runs, the
            // example's `vllm` survives, and every `noo chat` on the box
            // asked its Ollama for the vLLM default model (2026-09-28
            // rehearsal). The launcher's static fallback serves
            // OLLAMA_MODEL (default gemma4:e2b), so that is the model.
            let ollama_model = {
                let m = ctx.read_env("OLLAMA_MODEL");
                if m.is_empty() { "gemma4:e2b".to_string() } else { m }
            };
            if !ctx.dry_run {
                super::yamlcfg::update_yaml_config(ctx, "ollama", &ollama_model);
            }
        } else {
            ctx.info("No vLLM model configured — skipping vLLM placement (ollama/llamacpp need none).");
        }
        return;
    }
    if let Ok(t) = tier.parse::<i64>() {
        if t > 1 {
            ctx.info(&format!("Node tier {t} — skipping vllm placement (needs tier 1 GPU)"));
            return;
        }
    }
    if ctx.dry_run {
        ctx.dry(&format!("PUT vllm placement: {node_id} → {model} (tls, port 8000)"));
        return;
    }
    let mut body = serde_json::json!({"model": model, "desired_state": "running", "tls": true, "port": 8000});
    let image = ctx.read_env("VLLM_IMAGE");
    if !image.is_empty() {
        body["image"] = serde_json::json!(image);
    }
    let path = format!(
        "/api/cluster/nodes/{}/placements/vllm",
        crate::commands::urlencode(&node_id)
    );
    match crate::http::put_json_try(ctx.g, &path, &body, true, 10) {
        Ok(_) => ctx.success(&format!("vllm placement declared: {node_id} → {model} (agent converges within ~5 min)")),
        Err(e) => ctx.warn(&format!(
            "Could not declare vllm placement ({e}) — run: noo cluster place {node_id} vllm {model} --tls --port 8000"
        )),
    }
}

fn reset_grafana_password(ctx: &mut Ctx) {
    let pw = ctx.read_env("GRAFANA_PASSWORD");
    if pw.is_empty() {
        return;
    }
    let (code, _) = sh::docker_mut(
        ctx,
        &["exec", "noo-grafana", "grafana", "cli", "admin", "reset-admin-password", &pw],
    );
    if code == 0 {
        ctx.success("Grafana admin password synced with dashboard credentials");
    }
}

// The password rule lives in `crate::password_policy` (shared with the
// `noo security user` verbs and, byte-for-byte, the gateway).
use crate::password_policy::weak_password;

// ── Step 6: First Model ──────────────────────────────────────────────────

/// The Ollama model a fresh install starts with.
const PRODUCT_DEFAULT_MODEL: &str = "gemma4:e2b";

/// Which model the wizard offers as the default: the product default when
/// its download fits the box's budget or its size is unknown; otherwise the
/// first registry-verified pick, with a line saying why. Pure, so the rule
/// is pinned.
fn default_ollama_pick(
    product_default: &str,
    default_bytes: Option<u64>,
    budget_bytes: u64,
    starters: &[(String, String)],
) -> (String, Option<String>) {
    match (default_bytes, starters.first()) {
        (Some(bytes), Some((first, _))) if bytes > budget_bytes && first != product_default => (
            first.clone(),
            Some(format!(
                "{product_default} is the product default, but its {:.1} GB download is over this box's {:.1} GB fit — defaulting to {first} (registry-verified to fit). Pick {product_default} anyway to run it with partial offload.",
                bytes as f64 / 1e9,
                budget_bytes as f64 / 1e9
            )),
        ),
        _ => (product_default.to_string(), None),
    }
}

pub fn first_model(ctx: &mut Ctx) {
    // `--only model` skips the prereqs step, so the GPU tier was never
    // detected and the recommendations said "Tier 0" (2026-09-01). The
    // detection is one nvidia-smi call — just run it when state is empty.
    if ctx.state.tier == 0 {
        if let Some((gpu, vram)) = util::detect_gpu() {
            ctx.state.gpu_model = gpu;
            ctx.state.vram_gb = vram;
            ctx.state.tier = util::tier_for_vram(vram);
        } else {
            ctx.state.tier = 3; // CPU-only, never 0
        }
    }
    let has_anthropic = !ctx.read_env("ANTHROPIC_API_KEY").is_empty();
    let has_openai = !ctx.read_env("OPENAI_API_KEY").is_empty();
    let has_cloud = has_anthropic || has_openai;

    // Already-configured + cached?
    let existing_vllm = ctx.read_env("VLLM_MODEL");
    let standalone_box = ctx.repo_root.join(".noo-standalone").exists();
    if vllm_shortcut_applies(&existing_vllm, standalone_box) && hf_model_cached(ctx, &existing_vllm) {
        ctx.info(&format!("Model already downloaded: {existing_vllm}"));
        let keep = ctx.non_interactive || ctx.asker.confirm(&format!("Use cached model {existing_vllm}?"), true);
        if keep {
            ctx.state.model_pulled = existing_vllm.clone();
            ctx.state.backend_used = "vllm".to_string();
            ctx.update_env("VLLM_MODEL", &existing_vllm);
            yamlcfg::update_yaml_config(ctx, "vllm", &existing_vllm);
            ctx.success(&format!("Using cached model: {existing_vllm}"));
            return;
        }
    }

    // Services gate (audit item 7): with --skip-services (or a failed
    // services step) there is nothing to start a local backend against —
    // the old flow silently ran its own `docker compose up`, starting
    // containers the user explicitly asked not to start. Cloud config is
    // still fine: it only writes env.
    //
    // Finding #104 (rival-truth class): ctx.state.services_started is set
    // by THIS SESSION's services step — under `--only model` that step is
    // skipped and the flag lies about a stack the banner just called
    // "running". Probe reality before trusting the flag.
    if !ctx.state.services_started {
        let gateway_live = Command::new("docker")
            .args(["inspect", "-f", "{{.State.Running}}", &crate::envfile::container("gateway")])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
            .unwrap_or(false);
        if gateway_live {
            ctx.info("(services step skipped this run — stack found RUNNING; continuing)");
            ctx.state.services_started = true;
        }
    }
    if !ctx.state.services_started {
        ctx.info("Services are not running (services step skipped or failed) —");
        ctx.info("local model startup needs the stack. Start later with:");
        ctx.info("  noo stack start && noo onboard --only model");
        ctx.info("(the model step also STARTS the ollama container — a bare");
        ctx.info(" 'noo models pull' cannot; finding #103)");
        if has_cloud && !ctx.non_interactive
            && ctx.asker.confirm("Configure a CLOUD model instead? (no services needed)", false)
        {
            configure_cloud(ctx, has_anthropic, has_openai);
        }
        return;
    }

    if !ctx.non_interactive && !ctx.asker.confirm("Configure a first LLM now?", true) {
        ctx.info("Skipped. Run 'noo models pull <model>' later.");
        return;
    }

    // Backend selection. Ollama is the default everywhere the wizard runs
    // The stranger's box is one
    // machine, and vLLM there hung 900 s polling a port the service never
    // publishes, declared no placement, and left chat on a model nobody had
    // pulled. vLLM stays a CHOICE on a tier-1 repo install — a controller
    // that will place it — and is not offered on standalone, where the
    // embed ollama already holds the GPU.
    let standalone = ctx.repo_root.join(".noo-standalone").exists();
    let offer_vllm = ctx.state.tier == 1 && !standalone;
    let backend: String = if ctx.non_interactive {
        ctx.info("Auto-selected backend: ollama");
        "ollama".to_string()
    } else {
        ctx.info("1. Ollama — local inference, GGUF (recommended)");
        let mut max = 1;
        let vllm_choice = if offer_vllm {
            max += 1;
            ctx.info(&format!("{max}. vLLM — HuggingFace safetensors; for a controller that places it on tier-1 nodes"));
            Some(max)
        } else {
            None
        };
        let cloud_choice = if has_cloud {
            max += 1;
            ctx.info(&format!("{max}. Cloud API — no download, uses your API key"));
            Some(max)
        } else {
            None
        };
        let pick = ctx.asker.ask_choice("Select backend", 1, max, false);
        if vllm_choice == Some(pick) {
            "vllm".to_string()
        } else if cloud_choice == Some(pick) {
            "cloud".to_string()
        } else {
            "ollama".to_string()
        }
    };

    if backend == "cloud" {
        configure_cloud(ctx, has_anthropic, has_openai);
        return;
    }

    // Model selection: catalog recommendations + free-form. Same source as
    // `noo models recommended` (HF-backed, 24h cache, curated offline
    // fallback) — the previous hardcoded list had gone stale (audit item 5).
    if backend == "ollama" {
        // Origin scope default
        // this seed originally lived in the HINT block, which prints AFTER
        // the list was fetched — the hint claimed a scoping that never
        // applied and CN picks led the list). Seed BEFORE the query. Only
        // when unset — an existing choice (or exported env) is kept.
        if ctx.read_env("NOO_MODEL_ORIGINS").is_empty()
            && std::env::var("NOO_MODEL_ORIGINS").is_err()
        {
            ctx.update_env("NOO_MODEL_ORIGINS", "us");
            std::env::set_var("NOO_MODEL_ORIGINS", "us");
        }
        ctx.progress("Querying the Ollama registry for size-verified recommendations...");
    }
    let starters = starter_models(ctx.state.tier, &backend, ctx.state.vram_gb);
    // The offered default = the PRODUCT default
    // gemma4:e2b), not merely the first verified pick — a declared
    // OLLAMA_MODEL outranks both. The verified list stays as-is; gemma's
    // 7.2GB exceeds the strict 8GB fit and runs with partial offload,
    // which the line below says out loud rather than hiding the default.
    let declared = ctx.read_env("OLLAMA_MODEL");
    let mut default_note: Option<String> = None;
    let default_model = if backend == "ollama" {
        if !declared.is_empty() {
            declared.clone()
        } else {
            // On a 6 GB card the 7.2 GB product default was
            // forced past picks the registry had verified to fit, and
            // `--ci` took it. The default stays gemma4:e2b wherever it fits
            // (or its size cannot be read — do not hide it on a guess); on
            // a box it does not fit, the first verified pick is the default
            // and the line says why.
            let budget = crate::catalog::ollama_fit_budget_bytes(ctx.state.vram_gb);
            let bytes = if ctx.state.vram_gb > 0.5 && !ctx.dry_run {
                crate::catalog::ollama_download_bytes(PRODUCT_DEFAULT_MODEL, 8)
            } else {
                None
            };
            match default_ollama_pick(PRODUCT_DEFAULT_MODEL, bytes, budget, &starters) {
                (name, Some(why)) => { default_note = Some(why); name }
                (name, None) => name,
            }
        }
    } else {
        starters.first().map(|s| s.0.clone()).unwrap_or_default()
    };
    if let Some(why) = &default_note {
        ctx.info(why);
    }
    let model_name = if ctx.non_interactive {
        default_model.clone()
    } else {
        ctx.info(&format!("Recommended models for Tier {}:", ctx.state.tier));
        for (i, (name, desc)) in starters.iter().enumerate() {
            ctx.info(&format!("  {}. {name}  ({desc})", i + 1));
        }
        ctx.info("Or type a model name/ID directly.");
        if backend == "ollama" {
            ctx.raw("    Ollama takes LIBRARY names (qwen3:8b) or hf.co/<user>/<GGUF-repo>;");
            ctx.raw("    plain HF ids are translated to hf.co/… and must be GGUF repos.");
            ctx.raw("    Picks scoped by lab origin: NOO_MODEL_ORIGINS=us (default; widen: us,eu,cn — edit .env).");
            if declared.is_empty() && default_note.is_none() {
                ctx.raw(&format!("    Default {PRODUCT_DEFAULT_MODEL} = the product default."));
            }
        } else {
            ctx.raw("    vLLM takes HuggingFace repo ids (org/model), safetensors.");
        }
        let raw = ctx.asker.ask(&Prompt::new("Model (number or name)").default(default_model.clone()));
        if let Ok(idx) = raw.trim().parse::<usize>() {
            if idx >= 1 && idx <= starters.len() {
                starters[idx - 1].0.clone()
            } else {
                raw
            }
        } else if !raw.is_empty() {
            raw
        } else {
            default_model.clone()
        }
    };
    if model_name.is_empty() {
        ctx.warn("No model specified. Run 'noo models pull <model>' later.");
        return;
    }
    ctx.info(&format!("Selected: {model_name}"));

    if backend == "vllm" {
        start_vllm(ctx, &model_name);
    } else {
        pull_ollama(ctx, &model_name);
        verify_first_model(ctx);
        // No PAGEINDEX_LLM_MODEL here any more. It was written on standalone
        // when trellion dialled ollama directly and needed an exact name
        // (2026-09-07); trellion now asks the gateway (2026-09-09), where
        // `default` means every live chat node. An exact name written by
        // onboarding pinned every RAG answer to the one model chosen at
        // install (2026-10-17). The model still lands in the yaml as the
        // local backend's placement hint (`update_yaml_config`).
    }
}

/// Does a leftover `VLLM_MODEL` short-circuit the model step into "use the
/// cached vLLM model"? Never on a standalone box: vLLM is not offered there
/// (the embed Ollama holds the GPU), and a `.env` or HF cache kept from an
/// earlier install must not make the step skip the Ollama pull and leave the
/// vLLM repo id as the default chat model (i263a, take 12).
fn vllm_shortcut_applies(existing_vllm: &str, standalone: bool) -> bool {
    !existing_vllm.is_empty() && !standalone
}

/// A chat request body small enough to be a probe: the raw model call
/// (`context: false`, no coordinator, no conversation row), a few tokens.
/// `model` None asks for the default, the path a user's first `noo chat` takes.
fn chat_probe_body(model: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "prompt": "Reply with one short word.",
        "context": false,
        "max_tokens": 64,
        "channel": "cli",
    });
    if let Some(m) = model {
        body["model"] = serde_json::json!(m);
    }
    body
}

/// Did the gateway's answer to a probe come from a model? `POST
/// /api/inference` answers `{"success":true,"data":{"response":…}}`. An
/// empty response is still an answer (a thinking model can spend 64 tokens
/// on reasoning); only a refusal or an error is not.
fn chat_probe_answered(doc: &serde_json::Value) -> Result<(), String> {
    if doc["success"].as_bool() == Some(true) {
        return Ok(());
    }
    Err(doc["error"].as_str().unwrap_or("the gateway returned no answer").to_string())
}

/// A probe the wizard cannot make is not a model that cannot answer: no
/// stored login, or a credential the route refuses. Everything else
/// (timeout, 404 not served, 5xx, unreachable) is the install's fault.
fn probe_error_is_unverifiable(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    ["401", "403", "unauthorized", "forbidden", "not logged in", "log in", "login"]
        .iter()
        .any(|k| e.contains(k))
}

/// The pair of facts a first-model success must rest on: the configured
/// default chat model IS the one just pulled, or the sentence saying why not.
/// `read` is [`yamlcfg::configured_default`]'s answer.
fn default_model_mismatch(read: &Result<(String, String), String>, model: &str) -> Option<String> {
    match read {
        Ok((backend, m)) if backend == "ollama" && m == model => None,
        Ok((backend, m)) => Some(format!(
            "the default chat model is {backend}/{m}, not the {model} just pulled — chat would send {m} to the only Ollama. \
             Fix: noo models switch {model} --backend ollama"
        )),
        Err(why) => Some(format!(
            "the default chat model could not be recorded ({why}). Fix: noo models switch {model} --backend ollama"
        )),
    }
}

/// One probe, retried while the mesh has not yet heard the new model from
/// its node (a controller with a node agent learns of a fresh pull at the
/// next heartbeat; the gateway answers "not served by any node" until then).
/// Bounded: 5 tries, 10 s apart. Any other error returns at once.
fn chat_probe(ctx: &Ctx, model: Option<&str>) -> Result<(), String> {
    let body = chat_probe_body(model);
    let mut last = String::new();
    for attempt in 0..5 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
        match crate::http::post_json_try(ctx.g, "/api/inference", &body, true, 180)
            .and_then(|doc| chat_probe_answered(&doc))
        {
            Ok(()) => return Ok(()),
            Err(e) if model.is_some() && e.contains("is not served by any node") && attempt < 4 => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// After the pull: the model step does not report success until the default
/// chat model is the pulled model and a chat request for it is answered.
/// Before this the failure surfaced only at the later chat step, as a
/// 300 s stream timeout with the wrong model name (i263a).
fn verify_first_model(ctx: &mut Ctx) {
    let model = ctx.state.model_pulled.clone();
    if ctx.dry_run || model.is_empty() || ctx.state.backend_used != "ollama" {
        return;
    }
    if let Some(why) = default_model_mismatch(&yamlcfg::configured_default(ctx), &model) {
        let line = format!("model: {why}");
        ctx.error(&line);
        ctx.state.hard_failures.push(line);
        return;
    }
    ctx.progress(&format!("Checking that chat answers with {model} (one short request)..."));
    // 180 s: the first request loads the model into memory.
    match chat_probe(ctx, Some(&model)) {
        Ok(()) => {}
        Err(e) if probe_error_is_unverifiable(&e) => {
            ctx.warn(&format!("Could not check chat for {model} ({e}). Check it: noo chat --model {model} --message hi"));
            return;
        }
        Err(e) => {
            let line = format!(
                "model: {model} was pulled but a chat request for it failed: {e}. Check: noo cluster verify; noo chat --model {model} --message hi"
            );
            ctx.error(&line);
            ctx.state.hard_failures.push(line);
            return;
        }
    }
    ctx.success(&format!("Chat answers with {model}"));
    // The default (no model named) is what `noo chat` sends. The gateway
    // reads noomesh.yaml when it starts, so a gateway that was already up
    // keeps the old default until its next restart: say so, do not fail.
    if let Err(e) = chat_probe(ctx, None) {
        ctx.warn(&format!(
            "Chat with {model} named works, but the gateway's current default does not ({e}). \
             It reads the default at start: noo stack restart gateway"
        ));
    }
}

#[cfg(test)]
mod first_model_probe_tests {
    use super::{chat_probe_answered, chat_probe_body, default_model_mismatch, probe_error_is_unverifiable, vllm_shortcut_applies};

    #[test]
    fn a_leftover_vllm_model_does_not_short_circuit_a_standalone_install() {
        assert!(!vllm_shortcut_applies("Qwen/Qwen3-8B-AWQ", true));
        assert!(vllm_shortcut_applies("Qwen/Qwen3-8B-AWQ", false));
        assert!(!vllm_shortcut_applies("", false));
    }

    #[test]
    fn the_default_must_be_the_pulled_ollama_model() {
        let ok = Ok(("ollama".to_string(), "gemma4:e2b".to_string()));
        assert_eq!(default_model_mismatch(&ok, "gemma4:e2b"), None);
        let stale = Ok(("vllm".to_string(), "Qwen/Qwen3-8B-AWQ".to_string()));
        let why = default_model_mismatch(&stale, "gemma4:e2b").expect("a vllm default is not the pulled model");
        assert!(why.contains("vllm/Qwen/Qwen3-8B-AWQ") && why.contains("noo models switch gemma4:e2b --backend ollama"), "{why}");
        let missing = Err("noomesh.yaml does not exist".to_string());
        assert!(default_model_mismatch(&missing, "gemma4:e2b").unwrap().contains("could not be recorded"));
    }

    #[test]
    fn the_probe_is_a_bounded_raw_call_and_pins_only_when_asked() {
        let pinned = chat_probe_body(Some("gemma4:e2b"));
        assert_eq!(pinned["model"], "gemma4:e2b");
        assert_eq!(pinned["context"], false);
        assert!(pinned["max_tokens"].as_u64().is_some_and(|n| n <= 128));
        assert!(chat_probe_body(None).get("model").is_none(), "the default path names no model");
    }

    #[test]
    fn only_a_successful_answer_passes_the_probe() {
        assert!(chat_probe_answered(&serde_json::json!({"success": true, "data": {"response": ""}})).is_ok());
        let e = chat_probe_answered(&serde_json::json!({"success": false, "error": "model 'x' is not served by any node"})).unwrap_err();
        assert!(e.contains("not served"));
        assert!(chat_probe_answered(&serde_json::json!({})).is_err());
    }

    #[test]
    fn a_refused_login_is_unverifiable_but_a_timeout_or_404_is_a_failure() {
        assert!(probe_error_is_unverifiable("HTTP 401: Unauthorized"));
        assert!(!probe_error_is_unverifiable("the gateway is up but this answer took longer than 180s"));
        assert!(!probe_error_is_unverifiable("model 'x' is not served by any node; the only chat backend is the Ollama"));
    }

    #[test]
    fn the_model_step_verifies_after_the_pull() {
        let src = include_str!("steps.rs");
        let pull = src.find("        pull_ollama(ctx, &model_name);\n        verify_first_model(ctx);").expect("verify follows the pull");
        assert!(pull > 0);
    }
}

/// Starter suggestions from the shared models catalog — the same source
/// `noo models recommended` uses (HF-backed with the curated offline
/// fallback), so the wizard's picks track the catalog instead of a
/// hardcoded list that drifts (the old one still offered Qwen2.5 while
/// the catalog had moved on). Returns (model id, short description).
fn starter_models(tier: u8, backend: &str, vram_gb: f64) -> Vec<(String, String)> {
    // Ollama: LIVE, size-verified recommendations from the registry
    // (finding #41) — tags from ollama.com JSON, exact download bytes from
    // manifests, filtered to ~70% of this box's VRAM. The static trio below
    // is the OFFLINE fallback only (registry-verified 2026-08-25; refresh
    // by re-probing, never from memory).
    if backend == "ollama" {
        let effective_vram = if vram_gb > 0.5 {
            vram_gb
        } else if tier <= 2 {
            8.0
        } else {
            4.0
        };
        if let Some(live) = crate::catalog::ollama_live_starters(effective_vram) {
            return live;
        }
        let curated: &[(&str, &str)] = if tier <= 2 {
            &[
                ("qwen3:8b", "fast all-rounder, 8B (~5 GB)"),
                ("gemma4:e2b", "Google Gemma 4 E2B — current gen, light"),
                ("llama3.2:3b", "light + reliable, 3B"),
            ]
        } else {
            &[
                ("gemma4:e2b", "Gemma 4 E2B — current gen, light"),
                ("qwen3:4b", "small all-rounder, 4B"),
                ("llama3.2:1b", "tiny + capable, 1B"),
            ]
        };
        return curated.iter().map(|(n, d)| (n.to_string(), d.to_string())).collect();
    }
    // vLLM: the catalog's tier classifier buckets everything above 7B into
    // tier 1 and `model_class_for(1)` is None (no cap), so the raw list is
    // just the top HF hits by downloads — a fresh 16 GB box was offered
    // llama-3.3-70b-awq as the DEFAULT (host8 campaign, 2026-08-31).
    // Size-gate here: estimated weight bytes must fit in ~85% of VRAM
    // (4-bit quant ≈ 0.65 GB/B, fp16 ≈ 2.1 GB/B — same ballpark the
    // ollama path verifies against real manifests).
    let fits = |id: &str, params_b: f64| -> bool {
        if vram_gb <= 0.5 || params_b <= 0.0 {
            return true; // unknown VRAM or size — cannot judge, do not hide
        }
        let lower = id.to_lowercase();
        let quantized = ["awq", "gptq", "int4", "4bit", "-4b-", "nf4"]
            .iter()
            .any(|q| lower.contains(q));
        let gb_per_b = if quantized { 0.65 } else { 2.1 };
        params_b * gb_per_b <= vram_gb * 0.85
    };
    let mut cat = crate::catalog::Catalog::new();
    cat.fetch_models(backend, crate::catalog::model_class_for(tier as i64), 6, false)
        .iter()
        .filter(|m| {
            fits(
                m["id"].as_str().unwrap_or(""),
                m["params_b"].as_f64().unwrap_or(0.0),
            )
        })
        .take(3)
        .filter_map(|m| {
            let id = m["id"].as_str()?.to_string();
            let desc = match m["desc"].as_str().filter(|d| !d.is_empty()) {
                Some(d) => d.to_string(),
                None => {
                    let p = m["params_b"].as_f64().unwrap_or(0.0);
                    if p > 0.0 { format!("{p:.0}B") } else { String::new() }
                }
            };
            Some((id, desc))
        })
        .collect()
}

fn configure_cloud(ctx: &mut Ctx, has_anthropic: bool, has_openai: bool) {
    let use_anthropic = if has_anthropic && has_openai {
        ctx.info("1. Anthropic Claude (claude-sonnet-4-20250514)");
        ctx.info("2. OpenAI GPT (gpt-4o)");
        ctx.asker.ask_choice("Cloud provider", 1, 2, false) != 2
    } else {
        has_anthropic
    };
    let (model, provider) = if use_anthropic {
        ("claude-sonnet-4-20250514", "anthropic")
    } else {
        ("gpt-4o", "openai")
    };
    yamlcfg::enable_cloud_config(ctx, provider);
    ctx.state.model_pulled = model.to_string();
    ctx.state.backend_used = format!("cloud/{provider}");
    ctx.success(&format!("Cloud LLM configured: {model} via {provider}"));
    ctx.info("The coordinator will use this cloud API immediately — no download needed.");
}

fn hf_model_cached(ctx: &Ctx, model_name: &str) -> bool {
    let data_root = {
        let r = ctx.read_env("NOO_DATA_ROOT");
        if r.is_empty() { crate::commands::data_root::DEFAULT_DATA_ROOT.to_string() } else { r }
    };
    let safe = model_name.replace('/', "--");
    for base in [
        format!("{data_root}/hf-cache/models--{safe}"),
        format!("{data_root}/hf-cache/hub/models--{safe}"),
    ] {
        let snaps = Path::new(&base).join("snapshots");
        if !snaps.is_dir() {
            continue;
        }
        if let Ok(rd) = std::fs::read_dir(&snaps) {
            for e in rd.flatten() {
                if e.path().is_dir() {
                    if let Ok(files) = std::fs::read_dir(e.path()) {
                        for f in files.flatten() {
                            let name = f.file_name();
                            let name = name.to_string_lossy();
                            if name.ends_with(".safetensors") || name.ends_with(".bin") {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

fn pull_ollama(ctx: &mut Ctx, model: &str) {
    // A plain HF repo id ("google/gemma-4-E2B-it") is not an Ollama name —
    // Ollama wants library names or the hf.co/<repo> syntax, and passing it
    // verbatim died with an unhelpful "pull model manifest: file does not
    // exist" (finding #35). Translate, and say so.
    let translated: String;
    let model = if model.contains('/') && !model.starts_with("hf.co/") {
        translated = format!("hf.co/{model}");
        ctx.info(&format!(
            "HF-style id — pulling as {translated} (the repo must contain GGUF files)"
        ));
        &translated
    } else {
        model
    };
    yamlcfg::update_yaml_config(ctx, "ollama", model);
    // Standalone: ONE ollama. The always-on ollama-embed container is a
    // multi-model server — chat models pull into it, and no second
    // `ollama` service ever starts (the old path spun up a stray
    // noo-ollama beside it, 2026-09-01).
    let standalone = std::env::var("NOO_STANDALONE").as_deref() == Ok("1")
        || ctx.repo_root.join(".noo-standalone").exists();
    let target = if standalone { "noo-ollama-embed" } else { "noo-ollama" };
    if standalone {
        let embed_up = Command::new("docker")
            .args(["exec", target, "ollama", "list"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !embed_up && !ctx.dry_run {
            ctx.progress("Starting the ollama-embed container...");
            sh::run_compose(ctx, &["--profile", "standalone", "up", "-d", "--no-build", "ollama-embed"]);
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    } else {
        let ollama_up = sh::http_get_ok("http://localhost:11434/api/tags");
        if !ollama_up && !ctx.dry_run {
            ctx.progress("Starting Ollama container...");
            sh::run_compose(ctx, &["--profile", "controller", "up", "-d", "--no-build", "--force-recreate", "ollama"]);
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    }
    ctx.progress(&format!("Pulling {model} via Ollama (this may take several minutes)..."));
    if ctx.dry_run {
        ctx.dry(&format!("docker exec {target} ollama pull {model}"));
        ctx.update_env("OLLAMA_MODEL", model);
        ctx.state.model_pulled = model.to_string();
        ctx.state.backend_used = "ollama".to_string();
        return;
    }
    // The CHOICE is a config fact and the pull is only its fulfillment —
    // record it BEFORE pulling (finding #87: a registry 503 at 100% of a
    // 7.2GB gemma4 pull left .env without OLLAMA_MODEL, and the next stack
    // start would have downloaded the qwen3:8b default instead — the #70
    // bug resurfacing through the failure path). With the choice recorded,
    // the launcher's pre-pull fetches the RIGHT model on next start even
    // when this pull fails.
    ctx.update_env("OLLAMA_MODEL", model);
    // Stream pull output live (inherited stdio on the console; forwarded
    // Line events when the TUI owns the terminal).
    let mut cmd = Command::new("docker");
    cmd.args(["exec", target, "ollama", "pull", model]);
    let code = sh::stream_status(ctx, cmd);
    if code == 0 {
        // Record the choice where the LAUNCHER reads it (finding #70): the
        // start script pulls "${OLLAMA_MODEL:-gemma4:e2b}" on every stack
        // start when SOME model already exists there, otherwise skips the
        // default pull (2026-09-28: --skip-model was still downloading a
        // chat model without a choice recorded here — see
        // scripts/noomesh-start.sh)
        // (choice already recorded above — #70/#87)
        ctx.state.model_pulled = model.to_string();
        ctx.state.backend_used = "ollama".to_string();
        ctx.success(&format!("Model {model} pulled via Ollama"));
    } else {
        ctx.warn(&format!("Ollama pull did not complete — your choice IS saved (OLLAMA_MODEL={model}); the next stack start pulls it, or retry now: docker exec {target} ollama pull {model}"));
    }
}

/// The `vllm` service publishes no host port (the gateway reaches it on the
/// compose network), so polling localhost:8000 from the host could never
/// succeed — a guaranteed 900 s hang ending in "not yet ready". Ask inside
/// the container instead; the vLLM image carries python3, not curl.
///
/// The engine serves plain HTTP on 127.0.0.1 inside its door's network
/// namespace (`stunnel-vllm` holds the leaf and requires a client
/// certificate), so the probe asks it there, from inside.
fn wait_for_vllm(ctx: &Ctx, timeout_secs: u64) -> bool {
    if ctx.dry_run {
        return true;
    }
    let name = crate::envfile::container("vllm");
    let probe = VLLM_SELF_PROBE;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        let (code, _) = sh::docker(&["exec", &name, "python3", "-c", probe]);
        if code == 0 {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    false
}

/// The in-container vLLM readiness probe, shared with the compose
/// healthcheck and `scripts/noomesh-rebuild.sh` in shape: plain HTTP on
/// loopback. Pinned by a test against the compose file.
pub(crate) const VLLM_SELF_PROBE: &str = "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/v1/models',timeout=5)";

fn start_vllm(ctx: &mut Ctx, model: &str) {
    ctx.update_env("VLLM_MODEL", model);
    yamlcfg::update_yaml_config(ctx, "vllm", model);
    if ctx.dry_run {
        ctx.dry("docker compose --profile vllm up -d vllm (then poll /v1/models)");
        ctx.state.model_pulled = model.to_string();
        ctx.state.backend_used = "vllm".to_string();
        return;
    }
    if !hf_model_cached(ctx, model) {
        ctx.info("Model weights will be downloaded on first start (~5-15 min).");
    }
    ctx.progress("Starting vLLM container...");
    // --force-recreate: a pre-clean `noo-vllm` container left behind (deep
    // clean removes volumes/images, not stopped containers from the same
    // project) otherwise fails the up with "name already in use" (item 4).
    let (code, out) = sh::run_compose(ctx, &["--profile", "vllm", "up", "-d", "--no-build", "--force-recreate", "vllm"]);
    if code != 0 {
        ctx.warn(&format!("Failed to start vLLM: {}", out.chars().take(200).collect::<String>()));
        return;
    }
    ctx.state.backend_used = "vllm".to_string();
    ctx.progress("Waiting for vLLM engine (polls /v1/models inside the container; large models take a while)...");
    if wait_for_vllm(ctx, 900) {
        ctx.state.model_pulled = model.to_string();
        ctx.success(&format!("vLLM ready with {model}"));
        // Declared HERE, after VLLM_MODEL exists. The services step ran
        // ensure_llm_placement before the model step had chosen one, so it
        // always skipped, and nothing ever registered the backend.
        ensure_llm_placement(ctx);
    } else {
        ctx.warn("vLLM not yet ready (model may still be downloading). Check: docker logs noo-vllm");
    }
}

// ── Step 7: Channels ─────────────────────────────────────────────────────

/// Channel credentials are SECRETS: when the sops backend is active they
/// belong in secrets/env.sops, not plaintext .env (first-contact finding
/// #13 — the "no plaintext secrets at rest" promise silently excluded
/// channel tokens). The launcher loads the store before .env, so a
/// store-resident value wins; the .env copy is removed when the store
/// write succeeds. Plain-env installs keep today's behavior.
fn store_channel_secret(ctx: &mut Ctx, key: &str, value: &str) {
    // `update_env` honours --dry-run; the store write did not, so a dry run
    // that answered the Telegram prompt encrypted a real credential into
    // secrets/env.sops. "Mutate nothing" has no exceptions.
    if ctx.dry_run {
        ctx.dry(&format!("store {key} in secrets/env.sops (or .env when the backend is env)"));
        return;
    }
    let sops_active = ctx.read_env("NOO_SECRETS_BACKEND") == "sops"
        && ctx.repo_root.join("secrets/env.sops").exists();
    if sops_active {
        match crate::commands::secrets::store_upsert(&[(key.to_string(), value.to_string())]) {
            Ok(()) => {
                ctx.update_env(key, ""); // drop any plaintext copy
                ctx.info(&format!("{key} stored encrypted (secrets/env.sops)"));
                return;
            }
            Err(e) => ctx.warn(&format!(
                "{key}: sops store failed ({e}) — falling back to .env (plaintext)")),
        }
    }
    ctx.update_env(key, value);
}

pub fn channels(ctx: &mut Ctx) {
    if ctx.non_interactive {
        ctx.info("Skipped in non-interactive mode.");
        return;
    }
    ctx.state.channels.clear();
    // Channel credentials are container ENV: a running gateway only sees
    // them after a RECREATE (restart keeps the old env — host8
    // 2026-09-02, "restart to apply" was wrong advice). Track whether
    // anything changed and recreate once at the end of the step.
    let mut gateway_needs_recreate = false;
    let mut return_after_gchat = false;

    let existing_tg = ctx.read_env("TELEGRAM_BOT_TOKEN");
    let existing_wa = ctx.read_env("WHATSAPP_TOKEN");
    let existing_gc = ctx.read_env("GOOGLE_CHAT_KEY_FILE");

    ctx.info("Channels let you chat with Noomesh from messaging apps (Telegram, WhatsApp, Google Chat).");
    if !ctx.asker.confirm("Set up messaging channels?", !existing_tg.is_empty() || !existing_wa.is_empty() || !existing_gc.is_empty()) {
        ctx.info("Skipped. Run 'noo channels status' later.");
        return;
    }

    // Telegram
    if ctx.asker.confirm("Configure Telegram?", !existing_tg.is_empty()) {
        ctx.info("The token is the digits:letters string from BotFather's /token — not the t.me link. Guide: docs/channels/telegram.md");
        let mut token = ctx.asker.ask(&Prompt::new("Bot token (from @BotFather)").default(existing_tg.clone()).secret());
        // Validate at entry (host8 2026-09-02: the t.me link was pasted and
        // stored; every send and poll then 404'd until it was re-entered).
        // Bounded retries; a dry run skips the network.
        if !ctx.dry_run {
            for _ in 0..3 {
                let t = token.trim().to_string();
                if t.is_empty() {
                    break;
                }
                match telegram_get_me(&t) {
                    Ok(username) => {
                        ctx.success(&format!("Token verified: bot @{username}"));
                        token = t;
                        break;
                    }
                    Err(e) => {
                        ctx.warn(&format!("Telegram rejected that token: {e}"));
                        token = ctx.asker.ask(&Prompt::new("Bot token (blank = skip Telegram)").secret());
                    }
                }
            }
        }
        if token.trim().is_empty() {
            ctx.info("Telegram skipped.");
        }
        if !token.is_empty() {
            store_channel_secret(ctx, "TELEGRAM_BOT_TOKEN", &token);
            // The allow-list prompt is GONE. `TELEGRAM_ALLOWED_USERS` no
            // longer admits anyone — chat ingress is default-deny on a
            // channel link, so asking for a second list here would collect
            // a value the gateway ignores and leave the operator believing
            // they had configured access.
            let id = ctx.asker.ask(&Prompt::new(
                "Your numeric Telegram id (blank = link later; nobody can talk to the bot until a link exists)",
            ));
            if !id.trim().is_empty() {
                ctx.info(&format!(
                    "Link it after onboarding: noo security user link <your-username> telegram {}",
                    id.trim()
                ));
            } else {
                ctx.info("Link a sender with `noo security user link <username> telegram <id>` — until then the bot refuses every sender.");
            }
            ctx.state.channels.push("telegram".to_string());
            ctx.success("Telegram configured");
            gateway_needs_recreate = true;
        }
    }

    // WhatsApp
    if ctx.asker.confirm("Configure WhatsApp?", !existing_wa.is_empty()) {
        let token = ctx.asker.ask(&Prompt::new("Access token (Meta Business)").default(existing_wa).secret());
        let phone = ctx.asker.ask(&Prompt::new("Phone number ID").default(ctx.read_env("WHATSAPP_PHONE_ID")));
        // Two prompts fewer: the webhook verify token and app
        // secret were asked for and written, and nothing reads them — the
        // WhatsApp lane is outbound-only. Asking for a value with no reader
        // is a stranger's first "what is this for?".
        if !token.is_empty() && !phone.is_empty() {
            ctx.update_env("WHATSAPP_TOKEN", &token);
            ctx.update_env("WHATSAPP_PHONE_ID", &phone);
            ctx.state.channels.push("whatsapp".to_string());
            ctx.success("WhatsApp configured");
        }
    }

    // Google Chat
    // Absorbed = the STORE has the key. This used to ask whether
    // GOOGLE_CHAT_CREDENTIALS equalled the container path of a
    // materialised file; that file no longer exists, so the question had
    // stopped meaning anything. `load_sa_key(ctx, "")` reads the store,
    // which is the thing actually being asked about.
    let gc_absorbed =
        !Path::new(&existing_gc).is_file() && super::google_chat::load_sa_key(ctx, "").is_some();
    if ctx.asker.confirm("Configure Google Chat?", !existing_gc.is_empty() || gc_absorbed) {
        // Reconfigure after the key was absorbed: the plaintext was
        // shredded on purpose, so "file not found" was the wrong answer
        // (host8 2026-09-02). Offer the stored key, re-run discovery.
        if gc_absorbed
            && ctx.asker.confirm("Google Chat key is already in the encrypted store — keep it?", true)
        {
            ctx.state.channels.push("google_chat".to_string());
            ctx.success("Google Chat configured (stored key)");
            ask_watched_drive(ctx);
            if super::google_chat::discover(ctx, "") {
                gateway_needs_recreate = true;
            }
            return_after_gchat = true;
        }
        // Absolute default, resolved against the INSTALL ROOT — the old
        // "./secrets/…" default resolved against the shell's cwd, so the
        // wizard rejected a file that existed exactly where the default
        // claimed it looked (2026-09-01). Relative answers get the same
        // root treatment; ~ expands.
        let default_kf = if existing_gc.is_empty() {
            ctx.repo_root.join("secrets/service_account_key.json").to_string_lossy().into_owned()
        } else {
            existing_gc
        };
        if !return_after_gchat {
            ctx.info("Need the key? docs/channels/google-chat.md walks the GCP side (project, service account, Pub/Sub, Chat app).");
        }
        let answered = if return_after_gchat { String::new() } else {
            ctx.asker.ask(&Prompt::new("Path to service account key JSON").default(default_kf))
        };
        let key_file = {
            let a = answered.trim();
            if let Some(rest) = a.strip_prefix("~/") {
                format!("{}/{rest}", std::env::var("HOME").unwrap_or_default())
            } else if a.starts_with('/') {
                a.to_string()
            } else {
                ctx.repo_root.join(a.trim_start_matches("./")).to_string_lossy().into_owned()
            }
        };
        if return_after_gchat {
            // handled above
        } else if Path::new(&key_file).exists() {
            ctx.update_env("GOOGLE_CHAT_KEY_FILE", &key_file);
            // NOT GOOGLE_CHAT_CREDENTIALS=/app/google-chat-sa-key.json any
            // more: nothing materialises that file. The key travels as a
            // value from the store, and compose hands it to the gateway as
            // GOOGLE_CHAT_CREDENTIALS_JSON.
            ctx.state.channels.push("google_chat".to_string());
            ctx.success("Google Chat configured");
            ask_watched_drive(ctx);
            // Discover BEFORE absorb: the plaintext key is still readable.
            if super::google_chat::discover(ctx, &key_file) {
                gateway_needs_recreate = true;
            }
            // fu76: under the sops backend the file credential should live
            // IN the store, not plaintext beside it — absorb right here so
            // a security-focused install never has a bare key at rest.
            if !ctx.dry_run
                && ctx.read_env("NOO_SECRETS_BACKEND") == "sops"
                && ctx.asker.confirm(
                    "Absorb the key into the encrypted secret store? (plaintext shredded; \
                     the launcher materializes it at each start)", true)
            {
                let ok = Command::new("bash")
                    .arg(ctx.repo_root.join("scripts/noo-secrets-absorb-files.sh"))
                    .current_dir(&ctx.repo_root)
                    .status().map(|s| s.success()).unwrap_or(false);
                if ok {
                    ctx.success("key absorbed into secrets/env.sops (no plaintext at rest)");
                } else {
                    ctx.warn("absorb failed — the key stays plaintext; retry later: noo security secrets absorb-files");
                }
            }
        } else {
            ctx.warn(&format!("Key file not found: {key_file}"));
        }
    }
    if gateway_needs_recreate && !ctx.dry_run {
        let gateway_running = {
            let name = crate::envfile::container("gateway");
            Command::new("docker")
                .args(["ps", "-q", "--filter", &format!("name={name}")])
                .output()
                .map(|o| o.status.success() && !o.stdout.is_empty())
                .unwrap_or(false)
        };
        if gateway_running {
            ctx.progress("Recreating the gateway so the channel adapters start with these credentials...");
            let code = sh::run_script_streamed(ctx, "noomesh-restart.sh", &["--force", "gateway"]);
            if code == 0 {
                ctx.success("Gateway recreated — channels are live (verify: noo channels status).");
            } else {
                ctx.warn("Gateway recreate failed — run: noo stack restart --force gateway");
            }
        } else {
            ctx.info("Gateway not running yet — the upcoming launch starts the adapters with these credentials.");
        }
    }
}

/// `getMe` with the token: the bot's username on success, Telegram's
/// error text otherwise. 404 = the path is not a token (the t.me link,
/// a truncated paste); 401 = revoked.
fn telegram_get_me(token: &str) -> Result<String, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(15)))
        .build()
        .into();
    let mut resp = agent
        .get(&format!("https://api.telegram.org/bot{token}/getMe"))
        .call()
        .map_err(|e| format!("network: {e}"))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    let body: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    if status == 200 && body["ok"].as_bool() == Some(true) {
        return Ok(body["result"]["username"].as_str().unwrap_or("?").to_string());
    }
    let why = body["description"].as_str().unwrap_or("").to_string();
    Err(match status {
        404 => "HTTP 404 — that is not a bot token (paste the digits:letters string from BotFather's /token, not the t.me link)".to_string(),
        401 => "HTTP 401 — token revoked or wrong (BotFather /token shows the current one)".to_string(),
        _ => format!("HTTP {status} {why}"),
    })
}

/// Shared Google Drive to watch for auto-ingest. Same SA key as the Chat
/// bot (drive.rs), so it is asked right after Google Chat is configured.
/// Keyed by drive id — host-independent, unlike watched_folders — which is
/// why a fresh walk used to lose it silently: nothing asked.
fn ask_watched_drive(ctx: &mut Ctx) {
    let existing = yamlcfg::read_yaml_watched_drives(ctx);
    let default_id = existing.first().map(|(id, _)| id.clone()).unwrap_or_default();
    ctx.info("A shared Google Drive can be watched for auto-ingest into the knowledge base.");
    ctx.info("Share the drive with the service account's email first; the id is the last path segment of the drive's URL.");
    let answered = ctx.asker.ask(&Prompt::new("Shared Drive id to watch (blank = none)").default(default_id));
    let id = answered.trim().trim_end_matches('/').rsplit('/').next().unwrap_or("").trim().to_string();
    if id.is_empty() {
        if !existing.is_empty() {
            yamlcfg::update_yaml_watched_drives(ctx, &[]);
            ctx.info("Drive watching disabled.");
        }
        return;
    }
    let default_label = existing
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, l)| l.clone())
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "shared drive".to_string());
    let label = ctx.asker.ask(&Prompt::new("Label for this drive").default(default_label));
    let mut drives: Vec<(String, String)> = existing.into_iter().filter(|(i, _)| *i != id).collect();
    drives.insert(0, (id.clone(), label.trim().to_string()));
    yamlcfg::update_yaml_watched_drives(ctx, &drives);
    ctx.success(&format!("Watching shared Drive {id} (edit later: noo config set watched_drives ...)"));
}

/// The NOO_INSTANCE this onboard is namespacing, "" for the default install.
fn instance_name() -> String {
    match std::env::var("NOO_INSTANCE") {
        Ok(v) if !v.is_empty() && v != "mesh" => v,
        _ => String::new(),
    }
}

/// A non-default instance's data root must be its own directory.
/// Idempotent — a root that already carries the instance segment is kept, so
/// re-onboarding does not stack suffixes.
fn instance_scoped_root(root: &str, instance: &str) -> String {
    if instance.is_empty() {
        return root.to_string();
    }
    let seg = format!("/instances/{instance}");
    if root.trim_end_matches('/').ends_with(&seg) || root.contains(&format!("{seg}/")) {
        return root.to_string();
    }
    format!("{}{}", root.trim_end_matches('/'), seg)
}

// ── Step 10: Add-ons (free & licensed) ─────────────────────────────────

use crate::commands::addons::ADDON_ROWS;

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The add-ons step. Free add-ons are a yes/no with the current value as
/// default. Licensed ones are offered only when the installed entitlement
/// grants their feature; otherwise one line says what they are and the
/// flag is forced off (a gateway would refuse them anyway). If anything
/// changed and the stack is running, offer to apply now.
/// The MCP user door. The serve mapping for `/mcp/user`
/// is written unconditionally in the Tailscale step, but the door behind
/// it is a posture gate (`NOO_MCP_EXTERNAL_ENABLED`) that both vetted
/// profiles leave CLOSED — so before this an operator finished onboard
/// with a mapped path answering 401 and no hint of the two steps that
/// open it. It stays a question, never a default: the door is reachable
/// by anything that can reach the gateway, and opening it is the
/// operator's call. `--mcp-door` / `--no-mcp-door` pre-answer; `--ci`
/// without either leaves it closed.
pub fn mcp_door(ctx: &mut Ctx) {
    ctx.info("The MCP user door lets Claude Code (or any MCP client) on another tailnet machine use Noomesh as yourself, with a per-person key.");
    let open = match ctx.skip.mcp_door {
        Some(v) => v,
        None if ctx.non_interactive => false,
        None => ctx.asker.confirm("Open the MCP user door on the tailnet?", false),
    };
    if !open {
        ctx.state.mcp_door = Some(false);
        ctx.info("MCP user door stays closed. Open it later: noo security posture set NOO_MCP_EXTERNAL_ENABLED 1, then noo stack restart gateway.");
        return;
    }
    if ctx.dry_run {
        ctx.dry("set posture NOO_MCP_EXTERNAL_ENABLED=1 via the gateway, then restart the gateway");
        ctx.state.mcp_door = Some(true);
        return;
    }
    if !ctx.state.services_started {
        ctx.warn("The gateway is not running (services step skipped) — the posture gate lives in its database.");
        ctx.info("Once the stack is up: noo security posture set NOO_MCP_EXTERNAL_ENABLED 1, then noo stack restart gateway.");
        ctx.state.mcp_door = Some(false);
        return;
    }
    // The gate is a DB row (posture table), never .env or yaml — a row the
    // `noo config set` WRITE scope cannot reach (#420). Same route as
    // `noo security posture set`.
    // A posture write: the operator certificate the wizard issued, and a
    // token bound to it. Nothing else is admitted.
    ensure_operator_cert(ctx);
    match crate::http::post_json_operator_try(
        ctx.g,
        "/api/security/posture",
        &serde_json::json!({"key": "NOO_MCP_EXTERNAL_ENABLED", "value": "1"}),
        20,
    ) {
        Ok(_) => ctx.success("Posture gate NOO_MCP_EXTERNAL_ENABLED set to 1."),
        Err(e) => {
            ctx.warn(&format!("Could not set the posture gate ({e}) — run: noo security posture set NOO_MCP_EXTERNAL_ENABLED 1, then noo stack restart gateway"));
            ctx.state.mcp_door = Some(false);
            return;
        }
    }
    // Posture gates are read at gateway start.
    ctx.progress("Restarting the gateway so the door opens...");
    let code = sh::run_script_streamed(ctx, "noomesh-restart.sh", &["--force", "gateway"]);
    if code == 0 {
        ctx.success("MCP user door open.");
    } else {
        ctx.warn("Gateway restart failed — run: noo stack restart --force gateway (the gate is already set).");
    }
    ctx.state.mcp_door = Some(true);
    let door = if !ctx.state.ts_dnsname.is_empty() && ctx.state.ts_serve_applied {
        format!("https://{}/mcp/user", ctx.state.ts_dnsname)
    } else if !ctx.state.ts_ip.is_empty() {
        format!("https://{}:8080/mcp/user", ctx.state.ts_ip)
    } else {
        "https://<this-host>:8080/mcp/user".to_string()
    };
    ctx.info(&format!("Door URL: {door}"));
    ctx.info("Each person needs their own key: noo security service-key issue <name> --user <username> --scopes mcp  (shown once). Client config: docs/channels/mcp-your-client.md");
}

/// Issue and register the operator's client certificate
/// once the admin exists and the CLI is logged in as it. Idempotent: a held
/// certificate is left alone. Without a login there is no one to issue it
/// to, and the posture writes that follow are refused before they are sent
/// — the shared secret is not a fallback.
fn ensure_operator_cert(ctx: &mut Ctx) {
    let Some(account) = crate::credentials::load().map(|c| c.subject).filter(|s| !s.is_empty()) else {
        ctx.warn(
            "No CLI login, so no operator certificate — posture is NOT written. \
             Later: noo auth login, then noo security pki issue-client <you>.",
        );
        return;
    };
    if crate::operator_cert::load(&account).is_some() {
        return;
    }
    match crate::commands::pki::issue_and_register(ctx.g, &account, crate::operator_cert::OPERATOR_DAYS) {
        Ok((_, key, _)) => ctx.success(&format!(
            "Operator client certificate issued for {account} (key {}, 0600) — posture writes are now \
             attributable to you, not to the shared secret.",
            key.display()
        )),
        Err(e) => {
            ctx.warn(&format!("Operator certificate not issued: {e}"));
            ctx.info(&format!("Later: noo security pki issue-client {account} --force"));
        }
    }
}

/// Apply the `hardened` posture profile
/// distribution default" claim in the security architecture notes).
///
/// Before this, `noo onboard` never applied a profile at all: the doc said
/// hardened was the default, the `noo_security_posture` table was EMPTY on
/// every fresh install, and the gates fell back to whatever `.env` and
/// `noomesh.yaml` happened to say — which for the exec-approval gate was
/// `auto`, i.e. no gate. One route call makes the sentence true.
///
/// Not a question. Every gate in the bundle is either already the code default
/// or strictly more closed than it, so there is no convenience to trade away:
/// `apply-profile dev` is the deliberate opposite, and the wizard should not be
/// the place someone loosens a gate by pressing enter.
///
/// Does NOT restart the gateway here. Posture is read once at start, so the
/// rows land now and take effect at the next gateway start — and the gap is
/// safe in one direction only, which is the direction we are in: the running
/// process has no `NOO_EXEC_APPROVAL_MODE`, so it is at the code default
/// `strict`, which is TIGHTER than the `approval` the bundle sets. Restarting
/// mid-wizard, to loosen a gate, would be the wrong trade. The wizard's final
/// summary restarts the gateway ONCE if any gate is still pending, right
/// before `cluster verify` — an install must not end with its running posture
/// differing from the one it declares.
///
/// Its own function, called from the services step: everything it needs is a
/// running gateway.
pub fn security_posture(ctx: &mut Ctx) {
    if ctx.dry_run {
        ctx.dry("apply the `hardened` security posture profile via the gateway");
        return;
    }
    if !ctx.state.services_started {
        // Fail loud, with the exact command — the posture table lives in the
        // gateway's database, so there is nothing to write to yet.
        ctx.warn(
            "The gateway is not running, so the hardened security posture was NOT applied \
             — this install's security gates are at their code defaults, not the \
             distribution profile.",
        );
        ctx.info("Once the stack is up: noo security posture apply-profile hardened, then noo stack restart gateway.");
        return;
    }
    // The operator's own client certificate, now that the admin exists and
    // the CLI holds its login. Every posture write carries
    // it and a token bound to it; nothing else is admitted.
    ensure_operator_cert(ctx);
    match crate::http::post_json_operator_try(
        ctx.g,
        "/api/security/posture/profile",
        &serde_json::json!({"profile": "hardened"}),
        20,
    ) {
        Ok(v) => {
            let n = v["applied"].as_u64().unwrap_or(0);
            ctx.success(&format!("Hardened security posture applied ({n} gates, DB-authoritative)."));
            // The before/after diff the route returns. A count said nothing
            // about WHICH gate moved, and on a re-run the answer matters: a
            // profile covers every gate, so a door the operator opened by
            // hand is closed again here. That is correct — and it has to be
            // SAID, or the operator learns it from the door being shut.
            for row in v["changed"].as_array().into_iter().flatten() {
                let key = row["key"].as_str().unwrap_or("?");
                let to = row["to"].as_str().unwrap_or("?");
                match row["from"].as_str() {
                    Some(from) => {
                        ctx.warn(&format!("posture changed: {key} {from} → {to}"));
                        ctx.raw(&format!(
                            "    re-open it if that was deliberate: noo security posture set {key} {from}"
                        ));
                    }
                    None => ctx.info(&format!("posture set: {key} = {to} (was unset)")),
                }
            }
            if v["changed"].as_array().is_some_and(|a| a.is_empty()) {
                ctx.info("No gate moved — this install was already at the hardened profile.");
            }
            ctx.info("Exec approval is now `approval`: HIGH-risk tool calls wait for a human (dashboard Admin view, the chat card, or `noo approval approve <id>`). Active from the next gateway start; until then the gate is `strict` (deny).");
            ctx.info("Review or change it: noo security posture list / noo security posture set NOO_EXEC_APPROVAL_MODE <mode>");
        }
        Err(e) => {
            ctx.warn(&format!(
                "Could not apply the hardened security posture ({e}) — this install is \
                 NOT at the distribution profile."
            ));
            ctx.info("Run it yourself: noo security posture apply-profile hardened, then noo stack restart gateway.");
        }
    }
}

/// The voice add-on's models (i105): when voice is on, the controller
/// stages the configured whisper model and piper voice; the containers load
/// them read-only and offline. A failure is a warning with its retry line.
pub fn stage_voice_models(ctx: &mut Ctx) {
    if ctx.state.mode == "worker" || !crate::commands::voice_models::voice_on() {
        return;
    }
    if ctx.dry_run {
        for m in crate::commands::voice_models::configured() {
            ctx.dry(&format!("stage {} into {}", m.id(), crate::commands::voice_models::voice_root().display()));
        }
        return;
    }
    for r in crate::commands::voice_models::stage_configured(false) {
        let l = crate::commands::voice_models::line(&r);
        if r.is_ok() { ctx.success(&l) } else { ctx.warn(&l) }
    }
}

pub fn addons(ctx: &mut Ctx) {
    if ctx.state.mode == "worker" {
        ctx.info("Worker mode — add-ons run on the controller. Skipping.");
        return;
    }
    let now = now_ts();
    let licence = crate::entitlement::installed_token()
        .ok_or_else(|| "no entitlement installed".to_string())
        .and_then(|t| crate::entitlement::check(&t, now));
    match &licence {
        Ok(ent) => ctx.info(&format!("Entitlement: '{}' grants [{}].", ent.sub, ent.features.join(", "))),
        Err(why) => {
            ctx.info(&format!("Entitlement: none usable ({why})."));
            ctx.info("Licensed add-ons are listed for information; install one with");
            ctx.info("`noo security entitlement install <token>` then `noo onboard --only addons`.");
        }
    }

    let mut changed = false;
    for row in ADDON_ROWS {
        // `None` = not stated, which is NOT the same as off: it means the
        // add-on's own polarity applies, and the wizard should offer that as
        // the default rather than pre-answering "no".
        let declared = crate::onboard::yamlcfg::read_yaml_addon(ctx, row.key);
        let current = declared.unwrap_or(row.default_on);
        let kind = if row.licensed.is_some() { "licensed" } else { "free" };
        ctx.info("");
        ctx.info(&format!("{}  [{kind}]", row.title));
        for l in row.blurb {
            ctx.info(&format!("  {l}"));
        }
        let granted = match row.licensed {
            None => true,
            Some(feature) => licence.as_ref().map(|e| e.grants(feature)).unwrap_or(false),
        };
        let default = declared.unwrap_or(row.default_on);
        let want = if !granted {
            if current {
                ctx.warn("  was ON but the entitlement does not grant it — turning it off (the gateway refuses it anyway).");
            } else {
                ctx.info("  not licensed on this controller — leaving off.");
            }
            false
        } else if ctx.non_interactive {
            default
        } else {
            ctx.asker.confirm(&format!("Enable {}?", row.title), default)
        };
        if want != current || declared.is_none() {
            crate::onboard::yamlcfg::update_yaml_addon(ctx, row.key, want);
            if want != current {
                changed = true;
            }
        }
        if want && row.key == "evolve" && !ctx.dry_run {
            // Evolve needs its DB role + credentials minted (the systems
            // manifest owns that) — the same verb an operator would run.
            ctx.info("  minting evolve credentials (noo systems enable evolve) ...");
            let _ = crate::commands::systems::systems_enable(ctx.g, &["evolve".to_string()]);
        }
        ctx.success(&format!("{}: {}", row.title, if want { "on" } else { "off" }));
    }

    ctx.info("");
    // Service Setup ran the launcher with --core-only, so the deferrable
    // add-ons (evolve, trellion-intel, voice) are NOT running yet even when
    // the map already said yes. Gating this on `changed` alone would leave
    // them permanently unstarted on exactly the runs where the answers match
    // the file: a --reconfigure, a --from-archive restore, or a second pass
    // over an install someone already configured.
    let deferred_wanted = ADDON_ROWS.iter().any(|row| {
        matches!(row.key, "evolve" | "trellion_intel" | "voice")
            && crate::onboard::yamlcfg::read_yaml_addon(ctx, row.key).unwrap_or(row.default_on)
    });
    if !changed && !deferred_wanted {
        ctx.info("No add-on changes, and nothing deferred from Service Setup.");
        return;
    }
    if ctx.dry_run {
        ctx.dry("re-run the stack launcher so the chosen add-on profiles start/stop");
        return;
    }
    let apply = ctx.non_interactive
        || ctx.asker.confirm("Start the chosen add-ons now (re-runs the stack launcher)?", true);
    if !apply {
        ctx.info("Later: noo stack start   (profiles follow the addons: map in noomesh.yaml)");
        return;
    }
    let mut args: Vec<&str> = Vec::new();
    if ctx.read_env("NOO_INSTALL_MODE") == "dist" {
        args.push("--dist");
    }
    if std::env::var("NOO_STANDALONE").as_deref() == Ok("1") {
        args.push("--profile");
        args.push("standalone");
    }
    let code = sh::run_script_streamed(ctx, "noomesh-start.sh", &args);
    if code == 0 {
        ctx.success("Add-ons applied.");
    } else {
        ctx.warn("Stack launcher returned non-zero — run `noo stack start` and check `noo stack status`.");
    }
}

/// The summary's add-on lines: what is on, and for licensed ones whether
/// the gateway will actually honour it.
pub fn addons_summary(ctx: &Ctx) -> Vec<String> {
    let now = now_ts();
    let licence = crate::entitlement::installed_token()
        .ok_or_else(|| "no entitlement".to_string())
        .and_then(|t| crate::entitlement::check(&t, now));
    ADDON_ROWS
        .iter()
        .map(|row| {
            let on = crate::onboard::yamlcfg::read_yaml_addon(ctx, row.key)
                .unwrap_or(row.default_on);
            let state = match (on, row.licensed) {
                (false, _) => "off".to_string(),
                (true, None) => "on".to_string(),
                (true, Some(f)) => match &licence {
                    Ok(e) if e.grants(f) => format!("on (licensed to '{}')", e.sub),
                    _ => "on but UNLICENSED — the gateway refuses it".to_string(),
                },
            };
            let kind = if row.licensed.is_some() { "licensed" } else { "free" };
            format!("{:<40} {state}  [{kind}]", row.title)
        })
        .collect()
}

#[cfg(test)]
mod fu53_tests {
    use super::instance_scoped_root;

    #[test]
    fn default_install_root_is_untouched() {
        assert_eq!(instance_scoped_root("/mnt/d/noo", ""), "/mnt/d/noo");
    }

    #[test]
    fn instance_root_gets_its_own_directory() {
        assert_eq!(
            instance_scoped_root("/mnt/d/noo", "obtest"),
            "/mnt/d/noo/instances/obtest"
        );
        // Trailing slash must not produce a double slash.
        assert_eq!(
            instance_scoped_root("/mnt/d/noo/", "obtest"),
            "/mnt/d/noo/instances/obtest"
        );
    }

    #[test]
    fn suffixing_is_idempotent_across_reonboards() {
        let once = instance_scoped_root("/mnt/d/noo", "obtest");
        assert_eq!(instance_scoped_root(&once, "obtest"), once);
    }
}

#[cfg(test)]
mod plaintext_credential_tests {
    #[test]
    fn harrier_artifact_lives_under_the_release_namespace() {
        let r = super::harrier_artifact_ref();
        assert!(r.ends_with("/harrier:v1"), "{r}");
        assert!(r.starts_with("ghcr.io/"), "{r}");
        assert!(!r.contains("//"), "{r}");
    }

    use super::carry_plan;

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(k, x)| (k.to_string(), x.to_string())).collect()
    }

    /// The 2026-09-02 install: 22 encrypted secrets duplicated in plaintext.
    /// Every one must be selected; no config key may be. (The rule itself is
    /// `plaintext_env::plaintext_secret_keys`; this pins the wizard's use.)
    #[test]
    fn credentials_with_values_are_selected_and_config_is_not() {
        let env = pairs(&[
            ("NOO_JWT_SECRET", "abc"),
            ("NOO_CLUSTER_SECRET", "def"),
            ("REDIS_PASSWORD", "ghi"),
            ("HF_TOKEN", "hf_x"),
            ("NOO_TLS_KEY", "/path/key.pem"),
            ("NODE_ID", "host8"),
            ("NOO_IMAGE_TAG", "v0.2.26"),
            ("NOO_INSTALL_MODE", "dist"),
            ("NOO_SECRETS_BACKEND", "sops"),
            ("NOO_DATA_ROOT", "/mnt/d/noo"),
        ]);
        let got = crate::commands::plaintext_env::plaintext_secret_keys(&env);
        for k in ["NOO_JWT_SECRET", "NOO_CLUSTER_SECRET", "REDIS_PASSWORD", "HF_TOKEN"] {
            assert!(got.iter().any(|g| g == k), "{k} is a credential and must be carried");
        }
        for k in ["NODE_ID", "NOO_IMAGE_TAG", "NOO_INSTALL_MODE", "NOO_SECRETS_BACKEND", "NOO_DATA_ROOT"] {
            assert!(!got.iter().any(|g| g == k), "{k} is config and must stay in .env");
        }
    }

    /// An already-blank slot is not a plaintext copy.
    #[test]
    fn blank_values_are_not_plaintext_copies() {
        let env = pairs(&[("NOO_JWT_SECRET", ""), ("REDIS_PASSWORD", "   ")]);
        assert!(crate::commands::plaintext_env::plaintext_secret_keys(&env).is_empty());
    }

    /// Which copy wins follows what the stack was reading: .env on a
    /// plaintext install (every value carried, overwriting the store), the
    /// store on a sops install (only what it lacks is carried).
    #[test]
    fn the_carry_keeps_the_copy_the_stack_was_reading() {
        let env = pairs(&[("NOO_JWT_SECRET", "env-value"), ("TAVILY_API_KEY", "tvly")]);
        let stored = |k: &str| k == "NOO_JWT_SECRET";
        assert_eq!(carry_plan(&env, true, &stored), env, "plaintext install: .env was live");
        assert_eq!(
            carry_plan(&env, false, &stored),
            pairs(&[("TAVILY_API_KEY", "tvly")]),
            "sops install: the store's value stands"
        );
    }

    /// The store is armed BEFORE the first secret is minted, and there is no
    /// warn-and-continue branch: a missing or failing init script returns
    /// false from the step. (A plant that restores "leaving plaintext .env"
    /// fails here.)
    #[test]
    fn the_store_is_armed_before_any_secret_and_never_falls_back_to_plaintext() {
        let src = include_str!("steps.rs");
        let body = &src[src.find("pub fn secrets_setup(").expect("secrets_setup")..];
        let body = &body[..body.find("\n}\n").expect("end of secrets_setup")];
        let arm = body.find("if !arm_secret_store(ctx)").expect("secrets_setup arms the store");
        for mint in ["SECRETS {", "ctx.update_env(\"NOO_ADMIN_PASSWORD\"", "NOO_BACKUP_PASSPHRASE", "NOO_APP_DB_PASSWORD"] {
            let at = body.find(mint).unwrap_or_else(|| panic!("{mint} not in secrets_setup"));
            assert!(arm < at, "the store must be armed before `{mint}`");
        }
        let arm_fn = &src[src.find("fn arm_secret_store(").expect("arm_secret_store")..];
        let arm_fn = &arm_fn[..arm_fn.find("\n}\n").expect("end")];
        let plaintext_fallback = ["leaving", " plaintext .env"].concat();
        assert!(!arm_fn.contains(&plaintext_fallback), "a warn-and-continue fallback is back");
        assert!(!arm_fn.contains("ctx.warn(\"SOPS"), "a SOPS failure must refuse, not warn");
        assert_eq!(arm_fn.matches("return refuse_store(").count(), 4,
            "missing script, failing script, unreadable store, failed carry: each refuses");
    }
}

// ── Which interface the cluster plane listens on ─────────────────────────

/// Write an explicit `NOO_BIND_MODE`. Runs right after the Tailscale step,
/// so it knows whether this box has a tailnet IP.
///
/// Until 2026-09-24 the wizard never mentioned it and the launcher's unset
/// default is `all` — every cluster-plane port on every interface, including
/// (until 2026-09-29) the model cache's plaintext listener on 8083, which served model weights
/// with no authentication, and the admin login. Tolerable on our own
/// tailnet; on a stranger's LAN or VPS it publishes the cluster plane
/// Since 2026-09-29 the launcher
/// refuses an unset mode (`scripts/lib-bind-addr.sh`), so this answer is
/// what lets the services step start at all.
pub fn bind_mode(ctx: &mut Ctx) {
    let existing = ctx.read_env("NOO_BIND_MODE");
    if !existing.is_empty() {
        ctx.info(&format!("Cluster-plane bind: NOO_BIND_MODE={existing} (kept — change it in .env, confirm with: noo doctor exposure)"));
        return;
    }
    let has_tailnet = !ctx.state.ts_ip.is_empty();
    let default = if has_tailnet { "tailnet" } else { "local" };
    let chosen: &str = if ctx.non_interactive {
        default
    } else {
        ctx.info("Which interface should the cluster plane listen on? (gateway 8080, NATS, node-agent, model cache)");
        let mut n = 0;
        let tailnet_choice = if has_tailnet {
            n += 1;
            ctx.info(&format!("{n}. tailnet — this box's Tailscale IP only (recommended; nodes and devices reach it over the tailnet)"));
            Some(n)
        } else {
            None
        };
        n += 1;
        let local_choice = n;
        ctx.info(&format!("{n}. local — this machine only (a single box; add nodes later by switching to tailnet)"));
        n += 1;
        ctx.info(&format!("{n}. all — every network this machine is on, including the LAN or a public interface"));
        let default_idx = if has_tailnet { 1 } else { local_choice };
        let pick = ctx.asker.ask_choice("Bind mode", default_idx, n, false);
        if tailnet_choice == Some(pick) { "tailnet" } else if pick == local_choice { "local" } else { "all" }
    };
    ctx.update_env("NOO_BIND_MODE", chosen);
    ctx.success(&format!("Cluster-plane bind: NOO_BIND_MODE={chosen}"));
    if chosen == "tailnet" {
        make_tailnet_bind_survive_reboots(ctx);
    }
    if chosen == "all" {
        ctx.warn("Every published port is reachable from any network this machine is on — the gateway login, NATS and the mTLS model cache on 8443. Confirm with: noo doctor exposure");
    }
}

/// Tailnet mode binds the cluster plane to an address that exists only once
/// tailscaled is up, and docker.service does not wait for tailscaled. Without
/// `ip_nonlocal_bind=1` a reboot where Docker wins the race leaves the
/// gateway, NATS and the model cache down. Set it here, with
/// the sudo every other host step in this wizard already uses; never
/// silently: the operator sees the file it writes.
fn make_tailnet_bind_survive_reboots(ctx: &mut Ctx) {
    use crate::commands::doctor::{nonlocal_bind_enabled, nonlocal_bind_fix, NONLOCAL_BIND_DROPIN};
    if ctx.dry_run {
        ctx.dry(&format!("write {NONLOCAL_BIND_DROPIN} (net.ipv4.ip_nonlocal_bind=1) so the tailnet bind survives reboots"));
        return;
    }
    match nonlocal_bind_enabled() {
        Some(true) | None => return, // already safe, or not a Linux host
        Some(false) => {}
    }
    let fix = nonlocal_bind_fix();
    let go = ctx.non_interactive
        || ctx.asker.confirm(&format!(
            "Make the tailnet binding survive reboots? Writes {NONLOCAL_BIND_DROPIN} (uses sudo)"
        ), true);
    if !go {
        ctx.warn(&format!("Skipped — a reboot may leave the gateway down until the stack is restarted. Later: {fix}"));
        return;
    }
    // Non-interactive runs never prompt for a password: `sudo -n` fails fast
    // instead of hanging a CI or unattended install (the seam, i267).
    let ok = ctx_sudo(ctx)
        .args(["sh", "-c", &format!(
            "printf '%s\\n' 'net.ipv4.ip_nonlocal_bind=1' > {NONLOCAL_BIND_DROPIN} && sysctl -p {NONLOCAL_BIND_DROPIN} >/dev/null"
        )])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok && nonlocal_bind_enabled() == Some(true) {
        ctx.success(&format!("Tailnet bind survives reboots ({NONLOCAL_BIND_DROPIN})"));
    } else {
        ctx.warn(&format!("Could not set ip_nonlocal_bind — a reboot may leave the gateway down. Run: {fix}"));
    }
}

// ── Per-consumer service keys ────────────────────────────────────────────

/// The compose service a container name belongs to: `noo-worker` → `worker`.
fn service_of_container(ctx: &Ctx, container: &str) -> String {
    let prefix = {
        let p = ctx.read_env("NOO_CONTAINER_PREFIX");
        if p.is_empty() { "noo".to_string() } else { p }
    };
    container.strip_prefix(&format!("{prefix}-")).unwrap_or(container).to_string()
}

/// "svc:evolve granted: addon, temporal, … (addons/evolve/docker-compose.yml)" — the
/// line onboard prints for each key it mints.
pub(crate) fn grant_line(t: &crate::commands::secrets::ProvisionTargets) -> String {
    let scopes = crate::commands::secrets::provisioned_scopes(&t.consumer, &[]);
    let whence = t.overlay.as_deref().unwrap_or("core service, docker-compose.cluster.yml");
    format!("{} granted: {} ({whence})", t.consumer, scopes.join(", "))
}

/// Which of the required consumers have no ACTIVE key in the gateway's
/// listing. Pure over the JSON so the decision is pinned: an existing active
/// key is never re-minted by the wizard (a re-run must not rotate anything),
/// and an inactive row is not a key.
pub(crate) fn consumers_to_mint<'a>(
    required: &'a [(String, String)],
    listing: &serde_json::Value,
) -> Vec<&'a (String, String)> {
    let empty = Vec::new();
    let active: Vec<&str> = listing["keys"].as_array().unwrap_or(&empty).iter()
        .filter(|k| k["active"].as_bool().unwrap_or(false))
        .filter_map(|k| k["consumer"].as_str())
        .collect();
    required.iter().filter(|(_, consumer)| !active.contains(&consumer.as_str())).collect()
}

/// Mint, store and recreate the per-consumer gateway keys an install must
/// hold — `worker` always, plus each add-on that is on and calls the gateway.
///
/// Until 2026-09-24 nothing in the wizard minted these. Compose fell back to
/// an empty `NOO_SVC_KEY_*`, the consumer presented nothing, and the
/// fleet-wide shared-secret bridge (since deleted) quietly bought its
/// inference; `cluster verify` then failed every fresh install on the keys
/// row. This is `noo security service-key
/// provision` without its per-call whole-stack recreate: every missing key is
/// minted and stored first, then the consumers are recreated ONCE.
///
/// Called twice: after the core stack is healthy (worker, trellion) and
/// after the add-ons step (whatever it turned on). Idempotent: a consumer
/// with an active key is left alone.
pub fn provision_service_keys(ctx: &mut Ctx) {
    let addon_on = |name: &str| {
        crate::commands::addons::effective(name)
            .unwrap_or_else(|| crate::commands::addons::row(name).map(|r| r.default_on).unwrap_or(false))
    };
    let required = crate::commands::cluster_verify::required_service_keys(&addon_on);
    if ctx.dry_run {
        ctx.dry("mint + store + recreate the per-consumer service keys (worker, and each add-on that is on)");
        for (name, _) in &required {
            if let Some(t) = crate::commands::secrets::provision_targets(name) {
                ctx.dry(&grant_line(&t));
            }
        }
        return;
    }
    if !ctx.state.services_started {
        return;
    }
    if !ctx.sops_active() {
        ctx.info("Service keys need the encrypted store — provision later: noo security service-key provision worker");
        return;
    }
    // Both were written by THIS run — the store in step 3, the TLS paths in
    // step 5 — and the startup loader saw neither: without these two lines
    // the operator call below dialled plain http at a TLS gateway on a fresh
    // box (exit 3), and sent no credential on a re-run (401).
    hydrate_process_env(ctx);
    crate::envfile::reload_sops_secrets();
    // The wizard's own admin login (`ensure_cli_login`) — never a shared
    // secret. Without one this is a named skip, not a fallback.
    let listing = match crate::http::get_json_try(ctx.g, "/api/security/service-keys", true, 10) {
        Ok(v) if v["keys"].as_array().is_some() => v,
        Ok(_) | Err(_) => {
            ctx.warn("Could not read the service-key list (is the CLI logged in? noo auth status) — keys not minted. Later: noo security service-key provision worker");
            return;
        }
    };
    let missing = consumers_to_mint(&required, &listing);
    if missing.is_empty() {
        ctx.info("Service keys: every required consumer already holds an active key");
        return;
    }
    let mut recreate: Vec<String> = Vec::new();
    for (name, consumer) in missing {
        let Some(t) = crate::commands::secrets::provision_targets(name) else {
            ctx.warn(&format!("{consumer}: not a per-consumer key in the secret registry — skipped"));
            continue;
        };
        let scopes = crate::commands::secrets::provisioned_scopes(&t.consumer, &[]);
        // No prompt here: enabling the add-on in the wizard is the operator's
        // act. But the grant is SAID, the same words `provision` would show.
        ctx.info(&grant_line(&t));
        let body = serde_json::json!({ "consumer": t.consumer, "scopes": scopes });
        let minted = match crate::http::post_json_try(ctx.g, "/api/security/service-keys", &body, true, 20) {
            Ok(v) => v,
            Err(e) => {
                ctx.warn(&format!("{}: mint failed ({e}) — later: noo security service-key provision {name}", t.consumer));
                continue;
            }
        };
        let Some(raw) = minted["key"].as_str().map(str::to_string) else {
            ctx.warn(&format!("{}: the gateway returned no key — later: noo security service-key provision {name}", t.consumer));
            continue;
        };
        if let Err(why) = crate::commands::secrets::store_provisioned(&t.secret_key, &raw) {
            // An active row nobody holds reads as "installed, not yet called".
            // Revoke what was minted so the listing tells the truth.
            let _ = crate::http::post_json_try(
                ctx.g, &format!("/api/security/service-keys/{}/revoke", t.consumer), &serde_json::json!({}), true, 20);
            ctx.warn(&format!("{}: minted but could not be stored ({why}) — revoked; later: noo security service-key provision {name}", t.consumer));
            continue;
        }
        ctx.forget_store_cache();
        ctx.success(&format!("{}: key minted and stored as {}", t.consumer, t.secret_key));
        for c in &t.containers {
            let svc = service_of_container(ctx, c);
            if !recreate.contains(&svc) {
                recreate.push(svc);
            }
        }
    }
    if recreate.is_empty() {
        return;
    }
    // One recreate for every consumer that gained a key, through the
    // launcher (`noo stack restart --force …` → noomesh-restart.sh): it is
    // the one place that resolves the install shape. A raw `compose up`
    // here asked for `noomesh/postgres-pgvector:latest`, the source-build
    // name, on a dist install that only holds the released tag (2026-09-27
    // newcomer rehearsal) — the stack it had just brought up went down.
    // Not `recreate_args` either: that adds every enabled add-on's services,
    // and at this point of the wizard the add-ons have not been asked about.
    ctx.progress(&format!("Recreating {} so they present their keys...", recreate.join(", ")));
    let mut argv: Vec<&str> = vec!["--force"];
    argv.extend(recreate.iter().map(String::as_str));
    if sh::run_script_streamed(ctx, "noomesh-restart.sh", &argv) != 0 {
        ctx.warn(&format!(
            "Recreate failed — the keys ARE stored; run: noo stack restart --force {}", recreate.join(" ")));
    }
}

#[cfg(test)]
mod hostd_tests {
    use super::{hostd_install_args, hostd_install_decision, looks_like_elf, HostdInstall};

    /// i251: `--ci` on a host with systemd. A terminal is only needed for
    /// sudo's password; with passwordless sudo the non-interactive run
    /// installs hostd like the interactive one does. Without either it
    /// skips, as before.
    #[test]
    fn ci_installs_hostd_when_sudo_needs_no_password() {
        assert_eq!(hostd_install_decision(true, false), HostdInstall::Interactive);
        assert_eq!(hostd_install_decision(true, true), HostdInstall::Interactive);
        assert_eq!(hostd_install_decision(false, true), HostdInstall::PasswordlessSudo, "a cloud image's default user, a CI box, the film's box");
        assert_eq!(hostd_install_decision(false, false), HostdInstall::Skip);
    }

    #[test]
    fn controller_mode_names_the_root_and_worker_mode_does_not() {
        let c = hostd_install_args("controller", "/home/alice/.noo");
        assert_eq!(c, ["install", "--root", "/home/alice/.noo", "--mode", "controller"]);
        let w = hostd_install_args("worker", "/home/alice/.noo");
        assert_eq!(w, ["install", "--mode", "worker"], "worker mode is always a system unit and takes no root");
    }

    #[test]
    fn only_an_elf_is_installed_as_the_privileged_helper() {
        assert!(looks_like_elf(b"\x7fELF\x02\x01\x01"));
        assert!(!looks_like_elf(b"<!DOCTYPE html>"), "a 404 page from the release lane must not become /usr/local/bin/noo-hostd");
        assert!(!looks_like_elf(b""));
    }
}

#[cfg(test)]
mod storage_default_tests {
    use super::{default_root_for, Mount};

    fn mount(path: &str) -> Mount {
        Mount { path: path.to_string(), fstype: "ext4".into(), free_gb: 100.0, total_gb: 200.0, is_system: false, label: String::new() }
    }

    #[test]
    fn a_mount_holding_home_defaults_to_the_standard_location() {
        // The data-root policy forbids a root inside a home directory. The
        // 2026-09-24 rehearsal's reason for a home default (sudo leaving
        // root-owned subdirs) is handled by ensure_root_dir creating the
        // root owned by the operator.
        assert_eq!(default_root_for(&mount("/home"), "/home/alice"), "/var/lib/noo");
        assert_eq!(default_root_for(&mount("/"), "/home/alice"), "/var/lib/noo");
    }

    #[test]
    fn a_windows_drive_is_never_a_default() {
        assert_eq!(default_root_for(&mount("/mnt/d"), "/home/alice"), "/var/lib/noo");
    }

    #[test]
    fn a_data_disk_that_does_not_hold_home_defaults_at_its_root() {
        assert_eq!(default_root_for(&mount("/mnt/data"), "/home/alice"), "/mnt/data/noo");
        // a prefix that is not a path component is not "holds home"
        assert_eq!(default_root_for(&mount("/ho"), "/home/alice"), "/ho/noo");
    }
}

#[cfg(test)]
mod password_tests {
    use super::weak_password;

    #[test]
    fn twelve_characters_of_nothing_special_pass() {
        assert_eq!(weak_password("correct-horse-battery", "admin"), None);
    }

    #[test]
    fn eleven_characters_are_too_short() {
        assert!(weak_password("elevenchars", "admin").unwrap().contains("12 characters"));
    }

    #[test]
    fn the_first_page_of_any_wordlist_is_refused_regardless_of_case() {
        assert!(weak_password("Password123!", "admin").is_some());
        assert!(weak_password("Administrator", "someone").is_some());
    }

    #[test]
    fn the_username_inside_the_password_is_refused() {
        assert!(weak_password("alice-is-the-admin", "alice").unwrap().contains("username"));
    }
}

#[cfg(test)]
mod default_pick_tests {
    use super::default_ollama_pick;

    fn starters() -> Vec<(String, String)> {
        vec![("qwen3:4b".to_string(), "2.6 GB download".to_string())]
    }

    #[test]
    fn the_product_default_is_offered_when_it_fits() {
        let (name, why) = default_ollama_pick("gemma4:e2b", Some(7_200_000_000), 11_200_000_000, &starters());
        assert_eq!(name, "gemma4:e2b");
        assert!(why.is_none());
    }

    #[test]
    fn a_default_that_does_not_fit_yields_to_the_first_verified_pick_and_says_why() {
        // A 6 GB card: budget 4.2 GB, gemma4:e2b is 7.2 GB.
        let (name, why) = default_ollama_pick("gemma4:e2b", Some(7_200_000_000), 4_200_000_000, &starters());
        assert_eq!(name, "qwen3:4b");
        let why = why.expect("the line says why");
        assert!(why.contains("7.2 GB") && why.contains("4.2 GB") && why.contains("qwen3:4b"));
    }

    #[test]
    fn an_unknown_size_never_hides_the_default() {
        let (name, why) = default_ollama_pick("gemma4:e2b", None, 4_200_000_000, &starters());
        assert_eq!(name, "gemma4:e2b");
        assert!(why.is_none());
    }

    #[test]
    fn with_no_verified_picks_the_default_stands() {
        let (name, _) = default_ollama_pick("gemma4:e2b", Some(7_200_000_000), 4_200_000_000, &[]);
        assert_eq!(name, "gemma4:e2b");
    }
}

#[cfg(test)]
mod service_key_tests {
    use super::{consumers_to_mint, grant_line};

    /// Onboard does not prompt, but it says what it grants and where the
    /// request came from — the same words `provision` would show.
    #[test]
    fn onboard_says_what_it_grants_and_who_declared_it() {
        let t = crate::commands::secrets::provision_targets("evolve").unwrap();
        let line = grant_line(&t);
        assert!(line.starts_with("svc:evolve granted: addon, temporal,"), "{line}");
        assert!(line.ends_with("(addons/evolve/docker-compose.yml)"), "{line}");
        let w = grant_line(&crate::commands::secrets::provision_targets("worker").unwrap());
        assert_eq!(w, "svc:worker granted: addon, chat, embeddings (core service, docker-compose.cluster.yml)");
    }

    fn required() -> Vec<(String, String)> {
        vec![("worker".into(), "svc:worker".to_string()), ("trellion".into(), "svc:trellion".to_string())]
    }

    #[test]
    fn a_consumer_with_an_active_key_is_left_alone_and_the_rest_are_minted() {
        let listing = serde_json::json!({"keys": [
            {"consumer": "svc:worker", "active": true},
        ]});
        let req = required();
        let m: Vec<&str> = consumers_to_mint(&req, &listing).iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(m, vec!["trellion"]);
    }

    #[test]
    fn an_inactive_row_is_not_a_key() {
        let listing = serde_json::json!({"keys": [
            {"consumer": "svc:worker", "active": false},
        ]});
        let req = required();
        let m: Vec<&str> = consumers_to_mint(&req, &listing).iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(m, vec!["worker", "trellion"]);
    }

    #[test]
    fn nothing_to_mint_when_every_consumer_is_active() {
        let listing = serde_json::json!({"keys": [
            {"consumer": "svc:worker", "active": true},
            {"consumer": "svc:trellion", "active": true},
        ]});
        let req = required();
        assert!(consumers_to_mint(&req, &listing).is_empty());
    }
}

#[cfg(test)]
mod daemon_json_tests {
    use super::merge_daemon_json;

    #[test]
    fn keeps_every_key_the_daemon_already_had() {
        // The nvidia runtime that step 1 writes, and log rotation: both were
        // deleted by the old `{"data-root": …}` overwrite.
        let before = r#"{"runtimes":{"nvidia":{"path":"nvidia-container-runtime"}},"log-driver":"json-file","log-opts":{"max-size":"10m"}}"#;
        let out = merge_daemon_json(before, "/data/docker").unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["data-root"], "/data/docker");
        assert_eq!(v["runtimes"]["nvidia"]["path"], "nvidia-container-runtime");
        assert_eq!(v["log-driver"], "json-file");
        assert_eq!(v["log-opts"]["max-size"], "10m");
    }

    #[test]
    fn a_missing_file_becomes_an_object_with_one_key() {
        let v: serde_json::Value = serde_json::from_str(&merge_daemon_json("", "/data/docker").unwrap()).unwrap();
        assert_eq!(v, serde_json::json!({"data-root": "/data/docker"}));
    }

    #[test]
    fn replaces_an_existing_data_root() {
        let v: serde_json::Value =
            serde_json::from_str(&merge_daemon_json(r#"{"data-root":"/old"}"#, "/new").unwrap()).unwrap();
        assert_eq!(v["data-root"], "/new");
    }

    #[test]
    fn refuses_to_guess_at_a_file_it_cannot_parse() {
        assert!(merge_daemon_json("{ not json", "/x").is_err());
        assert!(merge_daemon_json("[1, 2]", "/x").is_err());
    }
}

#[cfg(test)]
mod data_root_candidate_tests {
    use super::mount_candidates_from;

    // The listing a container sees: Docker bind-mounts three FILES from the
    // host's root filesystem, plus a read-only bind mount, plus the usual
    // pseudo and boot mounts. Only real, writable directories may be offered
    // as a data root — the 2026-09-27 rehearsal auto-selected
    // /etc/resolv.conf/noo (a file) and then a read-only mount, in --ci.
    const CONTAINER: &str = "\
overlay / overlay rw,relatime,lowerdir=/x 0 0
proc /proc proc rw,nosuid 0 0
/dev/sdd /etc/resolv.conf ext4 rw,relatime,discard 0 0
/dev/sdd /etc/hostname ext4 rw,relatime,discard 0 0
/dev/sdd /etc/hosts ext4 rw,relatime,discard 0 0
/dev/sdd /sandbox ext4 ro,relatime,discard 0 0
/dev/sdd /var/lib/docker ext4 rw,relatime 0 0
/dev/sda1 /boot ext4 rw,relatime 0 0
tmpfs /run tmpfs rw,nosuid 0 0
/dev/sdb1 /srv/storage ext4 rw,relatime 0 0
/dev/sdc1 /mnt/d ntfs3 rw,relatime 0 0
";

    #[test]
    fn files_readonly_and_system_mounts_are_never_data_root_candidates() {
        let got = mount_candidates_from(CONTAINER);
        assert_eq!(got, vec!["/srv/storage".to_string(), "/mnt/d".to_string()], "{got:?}");
    }

    #[test]
    fn a_plain_root_and_a_spaced_mount_point_survive() {
        let got = mount_candidates_from("/dev/sda2 / ext4 rw,relatime 0 0\n/dev/sdb1 /media/big\\040disk xfs rw 0 0\n");
        assert_eq!(got, vec!["/".to_string(), "/media/big disk".to_string()]);
    }

    #[test]
    fn ro_is_matched_as_a_whole_option_not_a_substring() {
        // "errors=remount-ro" is not a read-only mount.
        let got = mount_candidates_from("/dev/sda2 /data ext4 rw,relatime,errors=remount-ro 0 0\n");
        assert_eq!(got, vec!["/data".to_string()]);
    }
}

#[cfg(test)]
mod grafana_door_step_tests {
    use crate::commands::grafana_door::{BIND_ADDR_KEY, ROOT_URL_KEY, TEST_ENV_LOCK};
    use crate::onboard::event::{PromptRequest, UiEvent, WizardUi};

    struct NullUi;
    impl WizardUi for NullUi {
        fn emit(&self, _: UiEvent) {}
        fn prompt(&self, _: &PromptRequest) -> String {
            String::new()
        }
        fn inherit_stdio(&self) -> bool {
            false
        }
    }

    /// A fresh onboard ends with Grafana single sign-on ON —
    /// `GRAFANA_ROOT_URL` (the gateway's `NOO_GRAFANA_URL`) and the matching
    /// published address written from the bind mode and tailnet identity.
    #[test]
    fn onboarding_turns_grafana_single_sign_on_on() {
        let _env = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let g = crate::Globals { json: false, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: true };
        let ui = NullUi;
        let mut ctx = crate::onboard::build_ctx(&g, &ui, true, false, crate::onboard::Skip::default());
        let dir = std::env::temp_dir().join(format!("noo-onboard-grafana-door-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        ctx.env_path = dir.join(".env");
        // What .env.example seeds and the bind-mode step writes.
        std::fs::write(&ctx.env_path, "NOO_BIND_MODE=tailnet\nGRAFANA_ROOT_URL=\nNOO_GRAFANA_BIND_ADDR=127.0.0.1\n").unwrap();
        ctx.state.ts_dnsname = "ctl.example.ts.net".into();
        ctx.state.ts_ip = "100.64.0.15".into();
        std::env::remove_var(ROOT_URL_KEY);
        std::env::remove_var(BIND_ADDR_KEY);
        std::env::remove_var(crate::commands::grafana_door::CONSOLE_URL_KEY);
        let fronted = std::cell::RefCell::new(Vec::new());
        let logins = std::cell::RefCell::new(Vec::new());
        let login = |port: u32, _: bool| {
            logins.borrow_mut().push(port);
            Ok(crate::tailnet_serve::Fronting::Written)
        };
        super::grafana_door_with(&mut ctx, &|port, _| {
            fronted.borrow_mut().push(port);
            Ok(crate::tailnet_serve::Fronting::Written)
        }, &login);
        assert_eq!(super::env::read_env_key(&ctx.env_path, ROOT_URL_KEY), "https://ctl.example.ts.net:3000", "SSO must be on after onboarding");
        // A bookmark of the tailnet door leads to the console's Open Grafana.
        assert_eq!(*logins.borrow(), vec![3000], "onboarding must map /login on Grafana's port");
        assert_eq!(
            super::env::read_env_key(&ctx.env_path, crate::commands::grafana_door::CONSOLE_URL_KEY),
            "https://ctl.example.ts.net/#/observability?open=grafana"
        );
        std::env::remove_var(crate::commands::grafana_door::CONSOLE_URL_KEY);
        // Tailnet mode: Grafana stays on loopback, and serve fronts its port
        // on the tailnet name (the browser gets the tailnet's certificate).
        assert_eq!(super::env::read_env_key(&ctx.env_path, BIND_ADDR_KEY), "127.0.0.1");
        assert_eq!(*fronted.borrow(), vec![3000], "onboarding must front Grafana's port with tailscale serve");
        // A local-mode controller fronts nothing.
        std::fs::write(&ctx.env_path, "NOO_BIND_MODE=local\nGRAFANA_ROOT_URL=\nNOO_GRAFANA_BIND_ADDR=127.0.0.1\n").unwrap();
        std::env::remove_var(ROOT_URL_KEY);
        fronted.borrow_mut().clear();
        logins.borrow_mut().clear();
        super::grafana_door_with(&mut ctx, &|port, _| {
            fronted.borrow_mut().push(port);
            Ok(crate::tailnet_serve::Fronting::Written)
        }, &login);
        assert!(fronted.borrow().is_empty(), "local mode must not touch tailscale serve");
        assert!(logins.borrow().is_empty(), "local mode must not touch tailscale serve");
        assert_eq!(super::env::read_env_key(&ctx.env_path, ROOT_URL_KEY), "https://localhost:3000");
        // tailnet mode, serve write FAILS: Grafana stays on the tailnet IP.
        std::fs::write(&ctx.env_path, "NOO_BIND_MODE=tailnet\nGRAFANA_ROOT_URL=\nNOO_GRAFANA_BIND_ADDR=127.0.0.1\n").unwrap();
        std::env::remove_var(ROOT_URL_KEY);
        std::env::remove_var(BIND_ADDR_KEY);
        super::grafana_door_with(&mut ctx, &|_, _| Err(crate::tailnet_serve::FrontError::Write("tailscaled is not running".into())), &login);
        assert!(logins.borrow().is_empty(), "no /login entry without a confirmed / entry");
        assert_eq!(super::env::read_env_key(&ctx.env_path, BIND_ADDR_KEY), "100.64.0.15",
            "an unconfirmed serve entry must keep the tailnet-IP publish");
        assert_eq!(super::env::read_env_key(&ctx.env_path, ROOT_URL_KEY), "https://ctl.example.ts.net:3000");
        std::env::remove_var(ROOT_URL_KEY);
        std::env::remove_var(BIND_ADDR_KEY);
        std::env::remove_var(crate::commands::grafana_door::CONSOLE_URL_KEY);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The step above is only worth its test while the wizard runs it.
    #[test]
    fn the_pki_step_runs_the_grafana_door() {
        let src = include_str!("steps.rs");
        let body = src.split("pub fn pki_enrollment(ctx: &mut Ctx) {").nth(1).expect("pki_enrollment exists");
        let body = body.split("\n}\n").next().unwrap();
        assert!(body.contains("\n    grafana_door(ctx);"), "pki_enrollment must call grafana_door");
    }

    /// Grafana's leaf names the tailnet door; other non-external services do not gain it.
    #[test]
    fn grafanas_leaf_names_the_tailnet_door() {
        let (dns, _) = super::service_cert_sans("grafana", "host", "10.0.0.2", "ctl.example.ts.net");
        assert!(dns.contains(&"ctl.example.ts.net".to_string()));
        let (dns, _) = super::service_cert_sans("prometheus", "host", "10.0.0.2", "ctl.example.ts.net");
        assert!(!dns.contains(&"ctl.example.ts.net".to_string()));
    }
}

/// By design, onboarding makes ZERO shared-secret calls.
///
/// The wizard's gateway-facing tail — the admin login, the service-key
/// listing, the operator certificate, the hardened posture and the MCP door —
/// is driven here against a recording fake gateway, interactive and
/// `--non-interactive`, fresh and re-run. Every request it receives is
/// counted; not one may carry an HMAC bearer, and the controller and fleet
/// secrets are SET in the environment the whole time, so code that reached
/// for them would be caught signing. (The full wizard needs docker; this is
/// every step of it that talks to the gateway as the operator.)
#[cfg(test)]
mod zero_hmac_onboard_tests {
    use crate::onboard::event::{PromptRequest, UiEvent, WizardUi};
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    struct ScriptUi {
        answers: Mutex<VecDeque<String>>,
        events: Mutex<Vec<String>>,
    }
    impl WizardUi for ScriptUi {
        fn emit(&self, ev: UiEvent) {
            self.events.lock().unwrap().push(format!("{ev:?}"));
        }
        fn prompt(&self, req: &PromptRequest) -> String {
            self.events.lock().unwrap().push(format!("PROMPT {}", req.label));
            self.answers.lock().unwrap().pop_front().unwrap_or_default()
        }
        fn inherit_stdio(&self) -> bool {
            false
        }
    }

    /// One recorded request: `METHOD path`, the Authorization header, body.
    #[derive(Debug, Clone)]
    struct Seen {
        line: String,
        auth: Option<String>,
        body: String,
    }

    fn is_hmac(auth: &str) -> bool {
        // `{actor}:{ts}:{32|64 hex}` — the only shape a shared-secret
        // bearer has, whoever signs it.
        let t = auth.trim().strip_prefix("Bearer ").unwrap_or(auth.trim());
        let parts: Vec<&str> = t.split(':').collect();
        parts.len() == 3
            && parts[1].chars().all(|c| c.is_ascii_digit())
            && matches!(parts[2].len(), 32 | 64)
            && parts[2].chars().all(|c| c.is_ascii_hexdigit())
    }

    /// A plain-HTTP gateway on loopback that answers by route and records
    /// every request until `stop`.
    fn fake_gateway(listing: serde_json::Value) -> (u16, Arc<Mutex<Vec<Seen>>>, Arc<std::sync::atomic::AtomicBool>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (seen2, stop2) = (seen.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop2.load(std::sync::atomic::Ordering::SeqCst) {
                let Ok((mut s, _)) = listener.accept() else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                };
                s.set_nonblocking(false).ok();
                s.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).to_string();
                        let len = head.lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            break;
                        }
                    }
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let raw = String::from_utf8_lossy(&buf).to_string();
                let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
                let line = head.lines().next().unwrap_or("").rsplit_once(' ').map(|(a, _)| a.to_string()).unwrap_or_default();
                let auth = head.lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                    .map(|l| l[l.find(':').unwrap() + 1..].trim().to_string());
                let path = line.split(' ').nth(1).unwrap_or("").split('?').next().unwrap_or("").to_string();
                let (status, extra, out) = match (line.split(' ').next().unwrap_or(""), path.as_str()) {
                    ("POST", "/auth/token") => (200, "Set-Cookie: noo_refresh=r1; HttpOnly; Path=/api/auth\r\n",
                        r#"{"access_token":"jwt-admin","token_type":"bearer","expires_in":900,"refresh_ttl_days":30}"#.to_string()),
                    ("GET", "/auth/me") => (200, "", r#"{"sub":"admin","scopes":["read","write","admin"],"role":"admin"}"#.to_string()),
                    ("GET", "/api/security/service-keys") => (200, "", listing.to_string()),
                    _ => (404, "", r#"{"detail":"not served by this fake"}"#.to_string()),
                };
                seen2.lock().unwrap().push(Seen { line, auth, body: body.to_string() });
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{out}",
                    out.len()
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        (port, seen, stop)
    }

    /// The listing that makes `provision_service_keys` mint nothing: every
    /// consumer it would require, active. (Minting would write the real
    /// store; the listing call is the credential under test.)
    fn full_listing() -> serde_json::Value {
        let addon_on = |name: &str| {
            crate::commands::addons::effective(name)
                .unwrap_or_else(|| crate::commands::addons::row(name).map(|r| r.default_on).unwrap_or(false))
        };
        let keys: Vec<serde_json::Value> = crate::commands::cluster_verify::required_service_keys(&addon_on)
            .into_iter()
            .map(|(_, c)| serde_json::json!({"consumer": c, "active": true}))
            .collect();
        serde_json::json!({ "keys": keys })
    }

    /// Run the gateway-facing tail of the wizard once; return what the fake
    /// gateway saw, the SQL the host path wrote, and the wizard's events.
    fn walk(non_interactive: bool, password_in_memory: bool, answers: &[&str], stored_login: bool) -> (Vec<Seen>, Vec<String>, Vec<String>) {
        let _env = crate::commands::grafana_door::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "noo-zero-hmac-{}-{}-{}-{}",
            std::process::id(), non_interactive, password_in_memory, stored_login
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("secrets")).unwrap();
        std::fs::create_dir_all(dir.join("pki-empty")).unwrap();
        std::fs::write(dir.join(".env"), "NOO_SECRETS_BACKEND=sops\nNOO_ADMIN_USER=admin\n").unwrap();
        std::fs::write(dir.join("secrets/env.sops"), "").unwrap();
        let creds = dir.join("creds/credentials.json");
        // The bait: both shared secrets set, and the old opt-in. Code that
        // reached for any of them would sign with it.
        let saved: Vec<(&str, Option<String>)> = [
            "NOO_CREDENTIALS_FILE", "NOO_PKI_DIR", "NOO_CONTROLLER_SECRET", "NOO_CLUSTER_SECRET", "NOO_BREAK_GLASS",
            "NOO_TOKEN", "NOO_OPERATOR", "NOO_OPERATOR_CERT_DIR", "NOO_GATEWAY_URL",
        ]
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect();
        std::env::set_var("NOO_CREDENTIALS_FILE", &creds);
        std::env::set_var("NOO_PKI_DIR", dir.join("pki-empty"));
        std::env::set_var("NOO_CONTROLLER_SECRET", "controller-bait");
        std::env::set_var("NOO_CLUSTER_SECRET", "fleet-bait");
        std::env::set_var("NOO_BREAK_GLASS", "1");
        for k in ["NOO_TOKEN", "NOO_OPERATOR", "NOO_OPERATOR_CERT_DIR", "NOO_GATEWAY_URL"] {
            std::env::remove_var(k);
        }
        let (port, seen, stop) = fake_gateway(full_listing());
        let base = format!("http://127.0.0.1:{port}");
        if stored_login {
            std::fs::create_dir_all(creds.parent().unwrap()).unwrap();
            std::fs::write(&creds, serde_json::json!({
                "version": 1, "gateway": base, "subject": "admin", "scopes": ["admin"],
                "access_token": "jwt-stored", "expires_at": u64::MAX / 2, "refresh_token": null, "refresh_expires_at": null,
            }).to_string()).unwrap();
        }
        crate::auth::forget_resolution();
        crate::host_access::TEST_SQL.with(|t| *t.borrow_mut() = Some(Vec::new()));

        let g = crate::Globals { json: false, verbose: false, gateway_override: Some(base), timeout_secs: Some(5), token: None, quiet: true };
        let ui = ScriptUi { answers: Mutex::new(answers.iter().map(|a| a.to_string()).collect()), events: Mutex::new(Vec::new()) };
        let skip = crate::onboard::Skip { mcp_door: Some(true), ..Default::default() };
        let mut ctx = crate::onboard::build_ctx(&g, &ui, non_interactive, false, skip);
        ctx.repo_root = dir.clone();
        ctx.env_path = dir.join(".env");
        ctx.secrets_dir = dir.join("secrets");
        ctx.pki_dir = dir.join("pki-empty");
        ctx.state.services_started = true;
        ctx.state.admin_username = "admin".into();
        if password_in_memory {
            ctx.state.admin_password = "the-password-this-run-set".into();
        }

        super::ensure_cli_login(&mut ctx);
        super::provision_service_keys(&mut ctx);
        super::security_posture(&mut ctx);
        super::mcp_door(&mut ctx);

        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let sql = crate::host_access::TEST_SQL.with(|t| t.borrow_mut().take()).unwrap_or_default();
        crate::auth::forget_resolution();
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        let events = ui.events.lock().unwrap().clone();
        let seen = seen.lock().unwrap().clone();
        let _ = std::fs::remove_dir_all(&dir);
        (seen, sql, events)
    }

    fn assert_zero_hmac(case: &str, seen: &[Seen]) {
        assert!(!seen.is_empty(), "{case}: the fake gateway saw nothing — the walk did not run");
        for s in seen {
            if let Some(a) = &s.auth {
                assert!(!is_hmac(a), "{case}: {} carried a shared-secret HMAC: {a}", s.line);
                assert!(!a.contains("bait"), "{case}: {} carried a secret: {a}", s.line);
            }
        }
        // The operator's calls carry the admin's own login.
        let listing = seen.iter().find(|s| s.line == "GET /api/security/service-keys")
            .unwrap_or_else(|| panic!("{case}: the service-key listing was never asked for: {seen:?}"));
        assert!(listing.auth.as_deref().is_some_and(|a| a.starts_with("Bearer jwt-")), "{case}: {listing:?}");
        // No posture write reached the gateway without the operator
        // certificate (there is none here, so none may be sent at all).
        assert!(!seen.iter().any(|s| s.line.starts_with("POST /api/security/posture")), "{case}: {seen:?}");
    }

    #[test]
    fn a_fresh_interactive_onboard_makes_zero_hmac_calls() {
        // Fresh: the password is in memory (step 3 just set it).
        let (seen, sql, events) = walk(false, true, &[], false);
        assert_zero_hmac("fresh interactive", &seen);
        let login = seen.iter().find(|s| s.line == "POST /auth/token").expect("the wizard logs in");
        assert!(login.body.contains("the-password-this-run-set") && !login.body.contains("host_ticket"), "{login:?}");
        assert!(sql.is_empty(), "a run with the password needs no host ticket: {sql:?}");
        assert!(events.iter().any(|e| e.contains("NOT at the distribution profile")), "no certificate here, so the posture write is refused before it is sent: {events:?}");
    }

    #[test]
    fn a_fresh_non_interactive_onboard_makes_zero_hmac_calls() {
        // --non-interactive generates the password and holds it in memory.
        let (seen, sql, _) = walk(true, true, &[], false);
        assert_zero_hmac("fresh --non-interactive", &seen);
        assert!(seen.iter().any(|s| s.line == "POST /auth/token" && s.body.contains("the-password-this-run-set")), "{seen:?}");
        assert!(sql.is_empty(), "{sql:?}");
    }

    /// The case `cli-onboard` existed for: a `--non-interactive` RE-RUN with
    /// no password in hand and no stored login. It logs in with a one-time
    /// host ticket — the ticket's hash written on the host, the ticket
    /// itself spent once at /auth/token — and still sends no HMAC.
    #[test]
    fn a_non_interactive_rerun_without_a_password_uses_a_host_ticket_not_a_secret() {
        let (seen, sql, _) = walk(true, false, &[], false);
        assert_zero_hmac("--non-interactive re-run", &seen);
        let login = seen.iter().find(|s| s.line == "POST /auth/token").expect("the wizard logs in");
        let body: serde_json::Value = serde_json::from_str(&login.body).expect("JSON login body");
        assert_eq!(body["grant_type"], "host_ticket", "{login:?}");
        assert_eq!(body["username"], "admin", "{login:?}");
        assert_eq!(sql.len(), 1, "one ticket: {sql:?}");
        assert!(sql[0].contains("INSERT INTO noo_host_login_tickets") && sql[0].contains("'admin'") && sql[0].contains("'onboard'"), "{sql:?}");
        let ticket = body["password"].as_str().expect("ticket in the body");
        assert!(ticket.starts_with(crate::host_access::TICKET_PREFIX), "{ticket}");
        assert!(sql[0].contains(&crate::host_access::ticket_hash(ticket)), "the row holds the hash of the ticket spent");
        assert!(!sql[0].contains(ticket), "the ticket itself never reaches psql");
    }

    /// An interactive re-run whose operator declines to type the password:
    /// the same host ticket, never the secret.
    #[test]
    fn an_interactive_rerun_that_declines_the_password_uses_a_host_ticket() {
        let (seen, sql, events) = walk(false, false, &["n"], false);
        assert_zero_hmac("interactive re-run, declined", &seen);
        assert!(events.iter().any(|e| e.contains("PROMPT Log your CLI in as 'admin'")), "{events:?}");
        assert_eq!(sql.len(), 1, "{sql:?}");
    }

    /// A re-run that already holds the admin's login uses it — no login, no
    /// ticket, and still no HMAC.
    #[test]
    fn a_rerun_with_a_stored_login_uses_it() {
        let (seen, sql, _) = walk(true, false, &[], true);
        assert_zero_hmac("re-run, logged in", &seen);
        assert!(!seen.iter().any(|s| s.line == "POST /auth/token"), "{seen:?}");
        assert!(sql.is_empty(), "{sql:?}");
        let listing = seen.iter().find(|s| s.line == "GET /api/security/service-keys").unwrap();
        assert_eq!(listing.auth.as_deref(), Some("Bearer jwt-stored"));
    }
}

#[cfg(test)]
mod service_cert_names_tests {
    use super::*;

    fn scratch() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("noo-1342-{}-{:x}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ca_with_short_leaf(svc: &str) -> (ClusterCa, std::path::PathBuf) {
        let dir = scratch();
        let ca = ClusterCa::new(dir.clone());
        ca.generate_ca("noo-test-ca", 3650).unwrap();
        // The shape found live: `model-cache, localhost, 127.0.0.1` only.
        ca.issue_service_cert(svc, &[], &[], DEFAULT_DAYS).unwrap();
        let crt = dir.join("services").join(svc).join("service.crt");
        (ca, crt)
    }

    /// An EXISTING leaf that misses the derived names is
    /// re-issued, and the new one carries them.
    #[test]
    fn a_short_existing_leaf_is_reissued_with_the_derived_names() {
        let (ca, crt) = ca_with_short_leaf("model-cache");
        let before = std::fs::read(&crt).unwrap();
        let out = ensure_service_cert_names(&ca, "model-cache", "Pop-Host", "10.0.0.5", "pop.ts.net").unwrap();
        match out {
            NamesOutcome::Reissued { missing, unreadable } => {
                assert!(unreadable.is_none());
                assert!(missing.contains(&"pop.ts.net".to_string()) && missing.contains(&"noo-controller".to_string()), "{missing:?}");
            }
            other => panic!("expected a re-issue, got {other:?}"),
        }
        assert_ne!(std::fs::read(&crt).unwrap(), before, "the leaf was not rewritten");
        let have = ClusterCa::cert_names(&crt).unwrap();
        assert!(have.dns.contains(&"pop.ts.net".to_string()) && have.ips.contains(&"10.0.0.5".to_string()));
        // And now it is covered: a second pass leaves it alone.
        assert_eq!(ensure_service_cert_names(&ca, "model-cache", "Pop-Host", "10.0.0.5", "pop.ts.net").unwrap(), NamesOutcome::Covered);
        let _ = std::fs::remove_dir_all(&ca.dir);
    }

    /// An unparseable leaf is ours to manage: re-issued, and the outcome
    /// says it could not be read. No leaf at all is not this pass's job.
    #[test]
    fn an_unreadable_leaf_is_reissued_and_says_so() {
        let (ca, crt) = ca_with_short_leaf("model-cache");
        std::fs::write(&crt, "garbage").unwrap();
        match ensure_service_cert_names(&ca, "model-cache", "h", "10.0.0.5", "").unwrap() {
            NamesOutcome::Reissued { unreadable: Some(_), .. } => {}
            other => panic!("expected an unreadable re-issue, got {other:?}"),
        }
        assert!(ClusterCa::cert_names(&crt).is_ok());
        assert_eq!(ensure_service_cert_names(&ca, "nats", "h", "", "").unwrap(), NamesOutcome::NoLeaf);
        let _ = std::fs::remove_dir_all(&ca.dir);
    }
}

#[cfg(test)]
mod compose_prereq_tests {
    use super::*;

    const UBUNTU: &str = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n";

    #[test]
    fn package_follows_distro_and_docker_source() {
        assert_eq!(compose_package(UBUNTU, false), Some("docker-compose-v2"));
        assert_eq!(compose_package(UBUNTU, true), Some("docker-compose-plugin"));
        assert_eq!(compose_package("ID=debian\n", false), Some("docker-compose-v2"));
        // a derivative is found through ID_LIKE
        assert_eq!(compose_package("ID=pop\nID_LIKE=\"ubuntu debian\"\n", true), Some("docker-compose-plugin"));
        // not Debian family: no package name is invented
        assert_eq!(compose_package("ID=fedora\n", false), None);
        assert_eq!(compose_package("", false), None);
        assert!(compose_remedy("ID=arch\n", false).contains("Compose v2 plugin"));
        assert!(compose_remedy(UBUNTU, false).contains("sudo apt install docker-compose-v2"));
    }

    fn fake_docker(name: &str, body: &str) -> String {
        let dir = std::env::temp_dir().join(format!("noo-compose-prereq-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("docker");
        crate::test_exec::write_exec(&bin, format!("#!/bin/sh\n{body}"), 0o755);
        bin.to_string_lossy().into_owned()
    }

    #[test]
    fn docker_that_answers_version_but_not_compose_fails_the_probe() {
        // Ubuntu docker.io: `docker --version` works, the compose shim errors rc=125.
        let d = fake_docker("nocompose", "if [ \"$1\" = compose ]; then echo \"unknown shorthand flag: 'f' in -f\" >&2; exit 125; fi\necho 'Docker version 29.1.3'\n");
        assert!(tool_version(&d).is_some(), "the fake answers --version");
        let err = probe_compose(&d).unwrap_err();
        assert!(err.contains("unknown shorthand flag"), "{err}");
    }

    #[test]
    fn present_compose_reports_its_version() {
        let d = fake_docker("hascompose", "[ \"$1 $2\" = \"compose version\" ] && { echo 'Docker Compose version v2.40.3'; exit 0; }\nexit 1\n");
        assert_eq!(probe_compose(&d).unwrap(), "v2.40.3");
    }

    #[test]
    fn a_missing_binary_is_a_failure_not_a_panic() {
        assert!(probe_compose("/nonexistent/docker").unwrap_err().contains("could not run"));
    }
}

#[cfg(test)]
mod dist_stack_lock_tests {
    use super::install_dist_stack_lock;
    use crate::release_fetch::{FetchClass, FetchError};
    use std::collections::HashMap;

    const TAG: &str = "v0.6.0-rc.3";
    const LOCK: &str = "gateway@sha256:aaaa\ntrellion@sha256:bbbb\nsource:trellion@0123abcd\n";

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("noo-onboard-lock-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A fake release: the files `stack-<tag>` publishes, signed by a test
    /// key, and the verifier that trusts only that key — the same shape as
    /// the baked release key, without it.
    struct FakeRelease {
        files: HashMap<(String, String), Vec<u8>>,
        pubkey: String,
    }

    impl FakeRelease {
        fn signed(lock: &str) -> Self {
            let key = crate::release_sig::signing_key_from_seed_hex(&"cd".repeat(32)).unwrap();
            let rel = format!("stack-{TAG}");
            let name = format!("{rel}.lock");
            let mut files = HashMap::new();
            files.insert((rel.clone(), name.clone()), lock.as_bytes().to_vec());
            files.insert((rel, format!("{name}.sig")), crate::release_sig::sign(&key, lock.as_bytes()).into_bytes());
            FakeRelease { files, pubkey: crate::release_sig::pubkey_hex(&key) }
        }

        fn install(&self, root: &std::path::Path) -> Result<usize, String> {
            let files = self.files.clone();
            let pk = self.pubkey.clone();
            install_dist_stack_lock(
                root,
                TAG,
                &mut |rel, name| {
                    files.get(&(rel.to_string(), name.to_string())).cloned()
                        .ok_or_else(|| FetchError::new(FetchClass::NotFound, format!("{rel}/{name}")))
                },
                &|data, sig| crate::release_sig::verify_with_keys(data, sig, &[pk.as_str()]),
            )
        }
    }

    #[test]
    fn a_verified_lock_is_written_for_the_tag_the_launcher_starts() {
        let root = scratch("ok");
        let n = FakeRelease::signed(LOCK).install(&root).expect("a signed lock installs");
        assert_eq!(n, 2, "two image rows pinned (the provenance row is not an image)");
        let written = std::fs::read_to_string(root.join("stack.lock")).unwrap();
        // The header the launcher matches (`^# tag ${DIST_TAG}$`) and the
        // reader the entitlement check uses both accept it.
        assert_eq!(written, format!("# tag {TAG}\n{LOCK}"));
        assert_eq!(crate::addons::resolve::installed_stack_lock(&root, TAG).as_deref().map(|t| t.contains("gateway@sha256:aaaa")), Some(true));
        assert!(!root.join(".stack.lock.tmp").exists(), "the temp file is renamed into place, not left behind");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_release_without_a_lock_refuses_and_writes_nothing() {
        let root = scratch("missing");
        let mut rel = FakeRelease::signed(LOCK);
        rel.files.clear();
        let err = rel.install(&root).expect_err("no lock is a refusal, never an unpinned start");
        assert!(err.contains("publishes no signed digest lock"), "{err}");
        assert!(!root.join("stack.lock").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_lock_that_does_not_verify_refuses_and_writes_nothing() {
        let root = scratch("tampered");
        let mut rel = FakeRelease::signed(LOCK);
        let key = (format!("stack-{TAG}"), format!("stack-{TAG}.lock"));
        rel.files.insert(key, b"gateway@sha256:evil\n".to_vec());
        let err = rel.install(&root).expect_err("a tampered lock refuses");
        assert!(err.contains("refusing to deploy"), "{err}");
        assert!(!root.join("stack.lock").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unsigned_lock_refuses() {
        let root = scratch("unsigned");
        let mut rel = FakeRelease::signed(LOCK);
        rel.files.retain(|(_, n), _| !n.ends_with(".sig"));
        let err = rel.install(&root).expect_err("an unsigned lock refuses");
        assert!(err.contains("without a signature"), "{err}");
        assert!(!root.join("stack.lock").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_dist_start_pins_the_lock_before_the_launcher_runs() {
        let src = include_str!("steps.rs");
        let body = &src[src.find("pub fn services(ctx: &mut Ctx)").expect("services step")..];
        let pin = body.find("if !pin_dist_stack_lock(ctx)").expect("the dist branch pins the lock");
        let launch = body.find("run_script_streamed(ctx, \"noomesh-start.sh\"").expect("the dist launch");
        assert!(pin < launch, "stack.lock must be verified and written before the launcher starts anything");
    }
}

#[cfg(test)]
mod llm_preference_hint_tests {
    use super::keep_llm_preference_hint;

    /// i145: a retired PAGEINDEX_LLM_MODEL that named a model becomes the
    /// command that keeps it as trellion's preference; the defaults do not.
    #[test]
    fn a_named_model_becomes_a_prefer_command_and_defaults_do_not() {
        assert_eq!(
            keep_llm_preference_hint("google/gemma-4-12B-it-qat-w4a16-ct").as_deref(),
            Some("noo cluster prefer knowledge google/gemma-4-12B-it-qat-w4a16-ct")
        );
        assert_eq!(keep_llm_preference_hint("\"gemma4:26b\"").as_deref(), Some("noo cluster prefer knowledge gemma4:26b"));
        for none in ["", "default", "Default", "knowledge", " auto "] {
            assert_eq!(keep_llm_preference_hint(none), None, "{none:?}");
        }
    }
}

#[cfg(test)]
mod sudo_seam_tests {
    use super::{ensure_root_dir, sudo_may_prompt, SUDO_BIN};
    use crate::onboard::event::{PromptRequest, UiEvent, WizardUi};

    /// `--ci` in a plain terminal: the wizard shares the terminal
    /// (`inherit_stdio` true), so the old gate (`-n` only when it does not)
    /// let sudo prompt and the run waited (take 14b, i267).
    struct TerminalUi;
    impl WizardUi for TerminalUi {
        fn emit(&self, _: UiEvent) {}
        fn prompt(&self, _: &PromptRequest) -> String {
            String::new()
        }
        fn inherit_stdio(&self) -> bool {
            true
        }
    }

    /// Only a person at a terminal the wizard does not own is asked.
    #[test]
    fn sudo_prompts_only_for_a_person_at_a_terminal_and_never_in_ci() {
        for ni in [false, true] {
            for inherit in [false, true] {
                for tty in [false, true] {
                    assert_eq!(sudo_may_prompt(ni, inherit, tty), !ni && inherit && tty, "non_interactive={ni} inherit_stdio={inherit} tty={tty}");
                }
            }
        }
    }

    /// Every onboard sudo is built by the seam: no raw sudo command and no
    /// per-site `-n` decision left in this file (the old sites decided on
    /// the UI, not on `--ci`, which is how 0.6.10–0.6.12-rc.1 prompted).
    #[test]
    fn every_onboard_sudo_goes_through_the_seam() {
        let src = concat!(include_str!("steps.rs"), include_str!("sandbox_apparmor.rs"));
        let raw = concat!("Command::new(", "\"sudo\")");
        let elevate = concat!("Command::new(", "elevate)");
        let ui_gate = concat!("if !ctx.ui.inherit_stdio() {\n", "        cmd.arg(\"-n\")");
        assert_eq!(src.matches(raw).count(), 0, "a raw sudo command in onboard: build it with sudo_cmd / ctx_sudo");
        assert_eq!(src.matches(elevate).count(), 0, "the CA trust install elevates through the seam");
        assert!(!src.contains(ui_gate), "a per-site -n decided on the UI instead of the seam");
    }

    /// i276: the same unwritable storage root, hit by the storage step, its
    /// summary and the services step's re-check, is ONE failure, the first.
    #[test]
    fn storage_is_one_failure_however_many_times_it_is_checked() {
        let dir = std::env::temp_dir().join(format!("noo-i276-storage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("sudo");
        crate::test_exec::write_exec(&fake, "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n", 0o755);
        SUDO_BIN.with(|b| *b.borrow_mut() = Some(fake.clone()));

        let g = crate::Globals { json: false, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: true };
        let ui = TerminalUi;
        let mut ctx = crate::onboard::build_ctx(&g, &ui, true, false, crate::onboard::Skip::default());
        ctx.env_path = dir.join(".env");
        // /proc refuses mkdir even for root, so every target falls through to sudo.
        let root = std::path::Path::new("/proc/noo-i276-data-root");
        let first = super::create_storage_dirs(&mut ctx, root);
        super::record_storage_summary_failure(&mut ctx, first, "/proc/noo-i276-data-root");
        let second = super::create_storage_dirs(&mut ctx, root);
        SUDO_BIN.with(|b| *b.borrow_mut() = None);

        assert!(first > 0 && second > 0, "the targets must be refused for this test to prove anything");
        let storage: Vec<_> = ctx.state.hard_failures.iter().filter(|f| f.starts_with("storage")).collect();
        assert_eq!(storage.len(), 1, "{:?}", ctx.state.hard_failures);
        assert!(storage[0].contains("sudo needs a password"), "the first failure is kept: {}", storage[0]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// i276: with a storage directory missing, the preflight refuses before
    /// any pull, and the same answer gates the repair retry; with them all
    /// present (or a dry run) it does not.
    #[test]
    fn a_missing_storage_directory_is_a_preflight_refusal() {
        let g = crate::Globals { json: false, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: true };
        let ui = TerminalUi;
        let mut ctx = crate::onboard::build_ctx(&g, &ui, true, false, crate::onboard::Skip::default());
        let dir = std::env::temp_dir().join(format!("noo-i276-preflight-{}", std::process::id()));
        let root = dir.join("data");
        std::fs::create_dir_all(&dir).unwrap();
        ctx.env_path = dir.join(".env");
        std::fs::write(&ctx.env_path, format!("NOO_DATA_ROOT={}\n", root.display())).unwrap();

        let (n, found_root, why) = super::storage_preflight_refusal(&ctx).expect("a missing data root must be refused");
        assert!(n > 0 && found_root == root.display().to_string(), "{n} {found_root}");
        assert!(why.contains("missing (Docker would create it root-owned)") && why.contains("nothing was pulled"), "{why}");

        ctx.dry_run = true;
        assert!(super::storage_preflight_refusal(&ctx).is_none(), "a dry run creates nothing and is never refused");
        ctx.dry_run = false;

        for (_, t) in super::storage_targets(&ctx, &root) {
            std::fs::create_dir_all(t).unwrap();
        }
        assert!(super::storage_preflight_refusal(&ctx).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The real data-root step, `--ci`, the wizard sharing a terminal, and a
    /// fake sudo that BLOCKS (sleeps 30 s) when called without `-n` and
    /// refuses with "a password is required" when called with it. The step
    /// must return at once, have called `sudo -n`, and record the refusal as
    /// a hard failure (the run then exits 1). On the old code this call had
    /// no `-n` and waited.
    #[test]
    fn ci_never_waits_on_a_sudo_prompt_and_says_so() {
        let dir = std::env::temp_dir().join(format!("noo-i267-sudo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("calls.log");
        let fake = dir.join("sudo");
        crate::test_exec::write_exec(
            &fake,
            format!(
                // printf, not echo: `echo "$@"` takes a leading `-n` as its own
                // flag and drops it from the log (the first batch run read
                // that as "no -n" and failed).
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n[ \"$1\" = \"-n\" ] || {{ sleep 30; exit 99; }}\necho 'sudo: a password is required' >&2\nexit 1\n",
                log.display()
            ),
            0o755,
        );
        SUDO_BIN.with(|b| *b.borrow_mut() = Some(fake.clone()));

        let g = crate::Globals { json: false, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: true };
        let ui = TerminalUi;
        let mut ctx = crate::onboard::build_ctx(&g, &ui, true, false, crate::onboard::Skip::default());
        let started = std::time::Instant::now();
        // /proc refuses mkdir even for root, so the step falls through to sudo.
        ensure_root_dir(&mut ctx, std::path::Path::new("/proc/noo-i267-data-root"));
        let took = started.elapsed();
        SUDO_BIN.with(|b| *b.borrow_mut() = None);

        assert!(took < std::time::Duration::from_secs(10), "the step waited {took:?}: a sudo without -n under --ci");
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(!calls.is_empty(), "the step never called sudo, so this test proves nothing");
        assert!(calls.lines().all(|l| l.starts_with("-n ")), "every sudo under --ci carries -n: {calls}");
        assert_eq!(ctx.state.hard_failures.len(), 1, "{:?}", ctx.state.hard_failures);
        let f = &ctx.state.hard_failures[0];
        assert!(f.starts_with("data root: sudo needs a password and this non-interactive run cannot ask — run: sudo install -d"), "{f}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // rc.2 (0.6.16): the hardened ollama image is uid 65532 with a root-owned
    // `/`, so a root-level staging dir cannot be created. Every path the
    // harrier step names must sit under the user's own store.
    #[test]
    fn harrier_staging_dir_is_under_the_non_root_store() {
        assert!(super::OLLAMA_CONVERT_DIR.starts_with("/home/nonroot/.ollama/"));
        assert!(!super::OLLAMA_CONVERT_DIR.starts_with("/convert"));
        let script = super::harrier_create_script("noo-ollama-embed", "/tmp/h");
        assert!(!script.contains(" /convert"), "{script}");
        assert!(!script.contains(":/convert"), "{script}");
        assert!(script.contains("mkdir -p /home/nonroot/.ollama/convert"), "{script}");
        assert!(script.contains("-w /home/nonroot/.ollama/convert noo-ollama-embed ollama create harrier"), "{script}");
        // Cleaned up after, and the verdict is ollama create's, not rm's.
        assert!(script.contains("rm -rf /home/nonroot/.ollama/convert >/dev/null 2>&1; exit $rc"), "{script}");
    }
}
