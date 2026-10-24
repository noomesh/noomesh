// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo-gateway harness probe` — run a kind's real vendor CLI once, the way
//! the driver runs it, against the node's own model or a scripted mock, and
//! report what happened.
//!
//! It proves, before a kind is placed, that "the CLI on this node, fed by our
//! own model" works: the translator wire, the launch flags, the env names,
//! the config file, the model-name handling. Each test is one invocation:
//!
//! 1. a [`Translator`] (with its probe-only request log) in front of the
//!    upstream — the pinned backend exactly as `harness_main` builds it
//!    (`tls::cluster_client()`, the node agent's bearer), or the in-process
//!    [`probe_mock`](super::probe_mock) model;
//! 2. a fresh workspace and HOME under the system temp dir, the CLI's
//!    environment from the driver's own [`build_env`] and launch recipe —
//!    with NO MCP and no gateway ([`McpWiring::None`]): no door key, no
//!    `mcpServers` file, no `[mcp_servers]` table;
//! 3. the CLI spawned through the driver's one spawn helper
//!    ([`spawn_cli_as`]: own process group, timeout, output caps), as an
//!    unprivileged user when the probe runs as root (`--run-as`, default
//!    `nobody`; uid 0 is refused);
//! 4. the verdict read with the driver's parser, and for `file` the file
//!    checked.
//!
//! It changes no service, no placement and no file outside its temp
//! workspace (removed unless `--keep`). In real mode it reads
//! `/etc/noo-harness.env` when readable, filling only variables not already
//! set — the model endpoint, `NOO_TLS_CA`/`NOO_TLS_CERT`/`NOO_TLS_KEY`, and
//! the node-agent bearer — the same values the harness unit gets.
//!
//! `--prompt full|slim` picks the launch for a kind with a slim one
//! (Claude Code): the full launch or `launch_slim`, so an operator can A/B
//! the two on a node. Without the flag, real mode asks the node's agent for
//! its harness profile (`claude_prompt`) and runs that; mock mode, or an
//! agent with no profile, runs full.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::json;

use super::driver::{self, build_env, fill_command_without_mcp, spawn_cli_as, with_system_prompt, DriverCtx, McpWiring, RunAs, RunOutput, Verdict, Workspace};
use super::profile::{model_context_of, resolve_claude_prompt, resolve_context_window, ClaudePrompt, HarnessProfile};
use super::probe_mock::{MockCall, MockModel, Script, PROBE_FILE, PROBE_WORD};
use super::translator::{RouteHit, Translator, UsageTotals};
use crate::coordinator::{self, ResolvedBackend};
use crate::harness_kinds::HarnessKind;

/// Where the harness unit's environment lives on a node.
pub const ENV_FILE: &str = "/etc/noo-harness.env";
/// The model name the mock answers under.
pub const MOCK_MODEL: &str = "noo-probe-mock";
pub const REPLY_PROMPT: &str = "Reply with exactly one line: NOO_RESULT: ok";
pub const FILE_PROMPT: &str = "Create a file named probe.txt in the current directory containing exactly the word noomesh. Then reply with exactly one line: NOO_RESULT: done";

pub const USAGE: &str = "usage: noo-gateway harness probe --kind <copilot|claude-code|codex> [--cli <path>] [--mock-model]
       [--model-url <url>] [--model <name>] [--backend <vllm|llamacpp|ollama|openai>]
       [--test <reply|file|both>] [--prompt <full|slim>] [--context-tokens <n>] [--timeout <secs>]
       [--run-as <user>] [--keep] [--json]

Runs the kind's vendor CLI once per test, as the harness driver does, against the
node's model (NOO_HARNESS_MODEL_URL/MODEL/BACKEND, else /etc/noo-harness.env) or,
with --mock-model, a scripted in-process model. No MCP, no gateway, no service or
placement change; the workspace is a temp dir, removed unless --keep. As root the
CLI runs as --run-as (default nobody), never as uid 0. --prompt picks Claude Code's full
or slim launch (default: the node's harness profile in real mode, else full).
--context-tokens tells a CLI that takes one (Claude Code) its model's context window
(default: the node agent's model_context in real mode, else the CLI's own). Exit 0
only if every test passed.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeTest {
    Reply,
    File,
}

impl ProbeTest {
    fn name(self) -> &'static str {
        match self {
            ProbeTest::Reply => "reply",
            ProbeTest::File => "file",
        }
    }

    fn prompt(self) -> &'static str {
        match self {
            ProbeTest::Reply => REPLY_PROMPT,
            ProbeTest::File => FILE_PROMPT,
        }
    }

    fn wanted(self) -> &'static str {
        match self {
            ProbeTest::Reply => "ok",
            ProbeTest::File => "done",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeArgs {
    pub kind: String,
    pub cli: Option<PathBuf>,
    pub mock_model: bool,
    pub model_url: Option<String>,
    pub model: Option<String>,
    pub backend: Option<String>,
    pub tests: Vec<ProbeTest>,
    /// `--prompt`: `None` = the node's profile in real mode, else full.
    pub prompt: Option<ClaudePrompt>,
    /// `--context-tokens`: `None` = the node agent's `model_context` in
    /// real mode, else unset.
    pub context_tokens: Option<u64>,
    pub timeout: u64,
    pub run_as: Option<String>,
    pub keep: bool,
    pub json: bool,
}

/// Parse the flags after `harness probe`. `--flag value` and `--flag=value`.
pub fn parse_args(args: &[String]) -> Result<ProbeArgs, String> {
    let mut a = ProbeArgs {
        kind: String::new(),
        cli: None,
        mock_model: false,
        model_url: None,
        model: None,
        backend: None,
        tests: vec![ProbeTest::Reply, ProbeTest::File],
        prompt: None,
        context_tokens: None,
        timeout: 300,
        run_as: None,
        keep: false,
        json: false,
    };
    let mut it = args.iter();
    while let Some(raw) = it.next() {
        let (flag, inline) = match raw.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (raw.as_str(), None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            inline.clone().or_else(|| it.next().cloned()).filter(|v| !v.trim().is_empty()).ok_or_else(|| format!("{name} needs a value"))
        };
        match flag {
            "--kind" => a.kind = value("--kind")?,
            "--cli" => {
                let p = PathBuf::from(value("--cli")?);
                if !p.is_absolute() {
                    return Err(format!("--cli must be an absolute path, got {}", p.display()));
                }
                a.cli = Some(p);
            }
            "--mock-model" => a.mock_model = true,
            "--model-url" => a.model_url = Some(value("--model-url")?),
            "--model" => a.model = Some(value("--model")?),
            "--backend" => {
                let b = value("--backend")?;
                if !["vllm", "llamacpp", "ollama", "openai"].contains(&b.as_str()) {
                    return Err(format!("--backend must be vllm, llamacpp, ollama or openai, got {b:?}"));
                }
                a.backend = Some(b);
            }
            "--test" => {
                a.tests = match value("--test")?.as_str() {
                    "reply" => vec![ProbeTest::Reply],
                    "file" => vec![ProbeTest::File],
                    "both" => vec![ProbeTest::Reply, ProbeTest::File],
                    other => return Err(format!("--test must be reply, file or both, got {other:?}")),
                }
            }
            "--prompt" => {
                let v = value("--prompt")?;
                a.prompt = Some(ClaudePrompt::parse(&v).ok_or_else(|| format!("--prompt must be full or slim, got {v:?}"))?);
            }
            "--context-tokens" => {
                a.context_tokens = Some(value("--context-tokens")?.parse().ok().filter(|n| *n > 0).ok_or("--context-tokens must be a positive number of tokens")?)
            }
            "--timeout" => a.timeout = value("--timeout")?.parse().ok().filter(|s| *s > 0).ok_or("--timeout must be a positive number of seconds")?,
            "--run-as" => a.run_as = Some(value("--run-as")?),
            "--keep" => a.keep = true,
            "--json" => a.json = true,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if a.kind.is_empty() {
        return Err("--kind is required".into());
    }
    if a.kind == "noo" {
        return Err("--kind noo is our own loop; the probe runs a vendor CLI (copilot, claude-code, codex)".into());
    }
    if crate::harness_kinds::get(&a.kind).is_none() {
        return Err(format!("unknown kind {:?} (known: {})", a.kind, crate::harness_kinds::names().join(", ")));
    }
    if a.prompt == Some(ClaudePrompt::Slim) && crate::harness_kinds::get(&a.kind).is_some_and(|k| k.launch_slim.is_none()) {
        return Err(format!("--prompt slim: kind {} has no slim launch (only claude-code has one)", a.kind));
    }
    if a.mock_model && (a.model_url.is_some() || a.backend.is_some()) {
        return Err("--mock-model serves its own model; drop --model-url/--backend".into());
    }
    Ok(a)
}

/// `KEY=VALUE` lines of an env file (systemd `EnvironmentFile` syntax, the
/// subset the renderer writes): comments and blanks skipped, one level of
/// matching quotes stripped.
pub fn parse_env_file(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let (k, v) = l.split_once('=')?;
            let k = k.trim().trim_start_matches("export ").trim();
            if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            let v = v.trim();
            let v = if v.len() >= 2 && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\''))) { &v[1..v.len() - 1] } else { v };
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// The file's values that the environment does not already set (an empty
/// variable counts as unset): the environment wins over the file.
pub fn env_file_fill(file: &[(String, String)], get: &dyn Fn(&str) -> Option<String>) -> Vec<(String, String)> {
    file.iter().filter(|(k, _)| get(k).is_none_or(|v| v.trim().is_empty())).cloned().collect()
}

/// The real upstream: flags, then the environment (which the env file has
/// already filled). Built as `harness_main` builds `pinned`.
pub fn resolve_backend(a: &ProbeArgs, get: &dyn Fn(&str) -> Option<String>) -> Result<ResolvedBackend, String> {
    let set = |k: &str| get(k).filter(|v| !v.trim().is_empty());
    let url = a.model_url.clone().or_else(|| set("NOO_HARNESS_MODEL_URL")).ok_or("no model endpoint: pass --model-url, set NOO_HARNESS_MODEL_URL, or run where /etc/noo-harness.env is readable (or use --mock-model)")?;
    let model = a.model.clone().or_else(|| set("NOO_HARNESS_MODEL")).ok_or("no model name: pass --model or set NOO_HARNESS_MODEL")?;
    let backend_type = a.backend.clone().or_else(|| set("NOO_HARNESS_BACKEND")).unwrap_or_else(|| "openai".into());
    Ok(ResolvedBackend { api_format: coordinator::api_format_for(&backend_type, &url), url, model, backend_type })
}

// ── who the CLI runs as ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RunAsUser {
    pub user: String,
    pub uid: u32,
    pub gid: u32,
}

#[cfg(unix)]
fn lookup_user(name: &str) -> Result<RunAsUser> {
    let c = std::ffi::CString::new(name).map_err(|_| anyhow!("bad user name {name:?}"))?;
    // SAFETY: getpwnam returns a pointer into static storage or null; the
    // fields are copied out before any other call.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        bail!("no such user {name:?}");
    }
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    Ok(RunAsUser { user: name.to_string(), uid, gid })
}

/// Who runs the CLI. As root: `--run-as` (default `nobody`), and never
/// uid 0. As anyone else: that user (a different `--run-as` cannot be
/// honoured without privilege, and is an error).
#[cfg(unix)]
pub fn decide_run_as(euid: u32, flag: Option<&str>, lookup: &dyn Fn(&str) -> Result<RunAsUser>) -> Result<Option<RunAsUser>> {
    if euid == 0 {
        let u = lookup(flag.unwrap_or("nobody"))?;
        if u.uid == 0 {
            bail!("refusing to run a vendor CLI as uid 0 ({}); --run-as an unprivileged user", u.user);
        }
        return Ok(Some(u));
    }
    match flag {
        None => Ok(None),
        Some(name) => {
            let u = lookup(name)?;
            if u.uid == euid {
                Ok(None)
            } else {
                bail!("--run-as {name} needs root (the probe runs as uid {euid})")
            }
        }
    }
}

#[cfg(unix)]
fn chown_tree(path: &Path, u: &RunAsUser) -> Result<()> {
    std::os::unix::fs::lchown(path, Some(u.uid), Some(u.gid)).with_context(|| format!("chown {}", path.display()))?;
    if path.is_dir() && !path.is_symlink() {
        for e in std::fs::read_dir(path)? {
            chown_tree(&e?.path(), u)?;
        }
    }
    Ok(())
}

// ── the report ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct TestReport {
    pub test: ProbeTest,
    pub pass: bool,
    pub reason: Option<String>,
    pub exit_code: Option<i32>,
    pub seconds: f64,
    pub timed_out: bool,
    pub verdict: Option<String>,
    pub routes: Vec<RouteHit>,
    pub usage: UsageTotals,
    pub mock: Option<Vec<MockCall>>,
    pub stdout_tail: String,
    pub stderr_tail: String,
    pub workspace: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Report {
    pub kind: String,
    pub cli: String,
    pub cli_version: Option<String>,
    pub mode: &'static str,
    pub model: String,
    pub backend: String,
    pub model_url: String,
    /// The launch variant run (`full`, or `slim` for a kind with one) and
    /// where the choice came from (`flag`, `profile`, `default`).
    pub prompt: ClaudePrompt,
    pub prompt_source: &'static str,
    /// The context window the CLI was told (`None` = not set: the kind
    /// takes none, or it is unknown) and where it came from (`flag`,
    /// `agent`, `default`).
    pub context_window: Option<u64>,
    pub context_source: &'static str,
    pub env_file: Option<String>,
    pub run_as: Option<RunAsUser>,
    pub tests: Vec<TestReport>,
    pub pass: bool,
}

fn verdict_text(v: &Verdict) -> Option<String> {
    match v {
        Verdict::Done(t) => Some(format!("NOO_RESULT: {t}")),
        Verdict::Failed(t) => Some(format!("NOO_FAILED: {t}")),
        Verdict::Ask(t) => Some(format!("NOO_QUESTION: {t}")),
        Verdict::Continue => None,
    }
}

/// PASS, or the first concrete reason it is not. `file` is the content of
/// `<workspace>/probe.txt` when it exists.
pub fn judge(test: ProbeTest, out: &RunOutput, routes: &[RouteHit], file: Option<&str>) -> (bool, Option<String>) {
    if out.timed_out {
        return (false, Some(format!("timed out after {}s", out.elapsed.as_secs())));
    }
    if out.code != Some(0) {
        let tail = driver::tail_lines(&out.stderr, 3);
        let tail = if tail.is_empty() { driver::tail_lines(&out.stdout, 3) } else { tail };
        return (false, Some(format!("{}: {tail}", out.code.map_or("killed by a signal".to_string(), |c| format!("exit {c}")))));
    }
    let v = driver::verdict(&out.stdout);
    let verdict_ok = v == Verdict::Done(test.wanted().into());
    if test == ProbeTest::File {
        match file.map(str::trim) {
            None => return (false, Some(format!("{PROBE_FILE} was not created in the workspace{}", hint(routes)))),
            Some(c) if c != PROBE_WORD => return (false, Some(format!("{PROBE_FILE} contains {c:?}, not {PROBE_WORD:?}"))),
            _ => {}
        }
    }
    if !verdict_ok {
        let got = verdict_text(&v).unwrap_or_else(|| "no NOO_RESULT line".into());
        return (false, Some(format!("verdict {got:?}, wanted \"NOO_RESULT: {}\"{}", test.wanted(), hint(routes))));
    }
    (true, None)
}

/// What the routes say about a failure: no call at all, or a non-2xx one.
fn hint(routes: &[RouteHit]) -> String {
    if routes.is_empty() {
        return " — the CLI never called the translator (did it take the bring-your-own-endpoint env?)".into();
    }
    match routes.iter().find(|r| !(200..300).contains(&r.status)) {
        Some(r) => format!(" — the translator answered {} to {} {}", r.status, r.method, r.path),
        None => String::new(),
    }
}

// ── running ─────────────────────────────────────────────────────────────

/// What one probe run needs, resolved.
pub struct Plan {
    pub kind: HarnessKind,
    pub cli: PathBuf,
    /// `None` = the mock.
    pub upstream: Option<ResolvedBackend>,
    pub tests: Vec<ProbeTest>,
    pub timeout: Duration,
    pub run_as: Option<RunAsUser>,
    pub keep: bool,
    pub env_file: Option<String>,
    /// The environment the driver context reads (PATH, LANG, NOO_TLS_CA).
    pub parent_env: BTreeMap<String, String>,
    /// Which launch runs (only a kind with a `launch_slim` is affected), and why.
    pub prompt: ClaudePrompt,
    pub prompt_source: &'static str,
    /// The window for `launch.context_window_env`, and why.
    pub context_window: Option<u64>,
    pub context_source: &'static str,
}

fn ctx_for(plan: &Plan, pinned: ResolvedBackend, base: &Path) -> Result<DriverCtx> {
    let mut e = plan.parent_env.clone();
    e.insert("NOO_HARNESS_WORKDIR".into(), base.display().to_string());
    e.insert("NOO_HARNESS_TURN_TIMEOUT_SECS".into(), plan.timeout.as_secs().to_string());
    // The gateway is never called: no MCP, no rail.
    let ctx = DriverCtx::new("probe", "http://127.0.0.1:9", &plan.kind, pinned, &|k| e.get(k).cloned())?;
    ctx.prompt.set(plan.prompt);
    ctx.context_window.set(plan.context_window);
    Ok(ctx)
}

fn run_as_ids(plan: &Plan) -> Option<RunAs> {
    plan.run_as.as_ref().map(|u| RunAs { uid: u.uid, gid: u.gid })
}

/// `<cli> --version`, first line, 10 s, in the kind's env.
async fn cli_version(plan: &Plan, base: &Path) -> Option<String> {
    let pinned = ResolvedBackend { url: "http://127.0.0.1:9".into(), model: MOCK_MODEL.into(), backend_type: "openai".into(), api_format: "openai".into() };
    let ctx = ctx_for(plan, pinned, base).ok()?;
    let ws = Workspace::create(base, "version", false).ok()?;
    // The CLI's own home exists in a real run (Codex warns without it).
    if ctx.launch.home_env.is_some() {
        let _ = std::fs::create_dir_all(ws.cli_home(plan.kind.cli.as_deref().unwrap_or(&plan.kind.kind)));
    }
    #[cfg(unix)]
    if let Some(u) = &plan.run_as {
        chown_tree(&ws.root, u).ok()?;
    }
    let env = build_env(&ctx, &ws, "http://127.0.0.1:9");
    let argv = vec![plan.cli.display().to_string(), "--version".to_string()];
    let jail = ws.jail_spec(&ctx, &ws.home);
    let out = spawn_cli_as(&argv, &env, &ws.work, Duration::from_secs(10), &jail, run_as_ids(plan), None).await;
    ws.finish();
    let out = match out {
        Ok(o) => o,
        Err(e) => return Some(format!("unknown (--version did not start: {e:#})")),
    };
    if out.timed_out {
        return Some("unknown (--version gave no answer within 10s)".into());
    }
    let lines: Vec<&str> = out.stdout.lines().chain(out.stderr.lines()).map(str::trim).filter(|l| !l.is_empty()).collect();
    lines.iter().find(|l| !l.to_ascii_lowercase().starts_with("warning") && l.chars().any(|c| c.is_ascii_digit())).or(lines.first()).map(|l| l.to_string())
}

async fn run_test(plan: &Plan, base: &Path, test: ProbeTest) -> Result<TestReport> {
    let ws = Workspace::create(base, test.name(), plan.keep)?;
    let mock = match plan.upstream {
        Some(_) => None,
        None => Some(MockModel::start(match test {
            ProbeTest::Reply => Script::Reply,
            ProbeTest::File => Script::File { workdir: ws.work.clone() },
        })
        .await?),
    };
    let pinned = match (&plan.upstream, &mock) {
        (Some(u), _) => u.clone(),
        (None, Some(m)) => ResolvedBackend { url: m.url().to_string(), model: MOCK_MODEL.into(), backend_type: "openai".into(), api_format: "openai".into() },
        (None, None) => unreachable!("a mock is started when there is no upstream"),
    };
    let full_ctx = ctx_for(plan, pinned.clone(), base)?;
    // The launch the driver would run for this variant.
    let (_, chosen) = full_ctx.run_ctx();
    let ctx: &DriverCtx = &chosen;
    let translator = Translator::start_logged(pinned).await.context("starting the wire translator")?;
    let run = async {
        let cli_config = ws.write_cli_config_wired(ctx, translator.base_url(), McpWiring::None)?;
        let system_prompt = ws.write_system_prompt(&ctx.launch)?;
        #[cfg(unix)]
        if let Some(u) = &plan.run_as {
            chown_tree(&ws.root, u)?;
        }
        let env = build_env(ctx, &ws, translator.base_url());
        let mut argv = fill_command_without_mcp(&with_system_prompt(&ctx.launch.command, system_prompt.as_deref()), test.prompt());
        argv[0] = plan.cli.display().to_string();
        tracing::info!(kind = %ctx.kind.kind, argv = ?argv, "probe: running the CLI");
        // The probe runs the CLI in the same jail the driver does: a probe
        // that passes unjailed would prove nothing about a real task.
        (ctx.jail_probe)().map_err(|r| anyhow!(r.note()))?;
        let jail = ws.jail_spec(ctx, cli_config.as_deref().unwrap_or(&ws.home));
        spawn_cli_as(&argv, &env, &ws.work, ctx.timeout, &jail, run_as_ids(plan), None).await
    }
    .await;
    let routes = translator.routes();
    let usage = translator.usage();
    translator.shutdown().await;
    let mock_calls = match mock {
        Some(m) => {
            let c = m.calls();
            m.shutdown().await;
            Some(c)
        }
        None => None,
    };
    let file = std::fs::read_to_string(ws.work.join(PROBE_FILE)).ok();
    let workspace = plan.keep.then(|| ws.root.display().to_string());
    ws.finish();
    let report = match run {
        Ok(out) => {
            let (pass, reason) = judge(test, &out, &routes, file.as_deref());
            TestReport {
                test,
                pass,
                reason,
                exit_code: out.code,
                seconds: (out.elapsed.as_secs_f64() * 10.0).round() / 10.0,
                timed_out: out.timed_out,
                verdict: verdict_text(&driver::verdict(&out.stdout)),
                routes,
                usage,
                mock: mock_calls,
                stdout_tail: driver::tail_lines(&out.stdout, 20),
                stderr_tail: driver::tail_lines(&out.stderr, 20),
                workspace,
            }
        }
        Err(e) => TestReport {
            test,
            pass: false,
            reason: Some(format!("could not run the CLI: {e:#}")),
            exit_code: None,
            seconds: 0.0,
            timed_out: false,
            verdict: None,
            routes,
            usage,
            mock: mock_calls,
            stdout_tail: String::new(),
            stderr_tail: String::new(),
            workspace,
        },
    };
    Ok(report)
}

/// Run every test of `plan`.
pub async fn run_plan(plan: &Plan) -> Result<Report> {
    driver::validate_kind(&plan.kind)?;
    let base = std::env::temp_dir().join(format!("noo-harness-probe-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?;
        if let Some(u) = &plan.run_as {
            chown_tree(&base, u)?;
        }
    }
    let version = cli_version(plan, &base).await;
    let mut tests = Vec::new();
    for t in &plan.tests {
        tests.push(run_test(plan, &base, *t).await?);
    }
    if !plan.keep {
        let _ = std::fs::remove_dir_all(&base);
    }
    let (model, backend, model_url) = match &plan.upstream {
        Some(u) => (u.model.clone(), u.backend_type.clone(), u.url.clone()),
        None => (MOCK_MODEL.to_string(), "openai".to_string(), "(in-process mock)".to_string()),
    };
    Ok(Report {
        kind: plan.kind.kind.clone(),
        cli: plan.cli.display().to_string(),
        cli_version: version,
        mode: if plan.upstream.is_some() { "real" } else { "mock" },
        model,
        backend,
        model_url,
        prompt: if plan.kind.launch_slim.is_some() { plan.prompt } else { ClaudePrompt::Full },
        prompt_source: plan.prompt_source,
        context_window: plan.context_window.filter(|_| plan.kind.launch.as_ref().is_some_and(driver::takes_context_window)),
        context_source: plan.context_source,
        env_file: plan.env_file.clone(),
        run_as: plan.run_as.clone(),
        pass: !tests.is_empty() && tests.iter().all(|t| t.pass),
        tests,
    })
}

fn find_on_path(prog: &str, path: &str) -> Option<PathBuf> {
    path.split(':').filter(|d| !d.is_empty()).map(|d| Path::new(d).join(prog)).find(|p| p.is_file())
}

fn print_human(r: &Report) {
    println!("harness probe: kind {} ({} model {} via {})", r.kind, r.mode, r.model, r.model_url);
    println!("  cli: {} — {}", r.cli, r.cli_version.as_deref().unwrap_or("version unknown"));
    println!("  launch: {} ({})", r.prompt.name(), r.prompt_source);
    if let Some(n) = r.context_window {
        println!("  context window: {n} tokens ({})", r.context_source);
    }
    if let Some(u) = &r.run_as {
        println!("  run as: {} (uid {})", u.user, u.uid);
    }
    for t in &r.tests {
        println!(
            "  {} {:<5} exit {} in {:.1}s{} — {}",
            if t.pass { "PASS" } else { "FAIL" },
            t.test.name(),
            t.exit_code.map_or("-".into(), |c| c.to_string()),
            t.seconds,
            if t.timed_out { " (timed out)" } else { "" },
            t.reason.as_deref().unwrap_or(t.verdict.as_deref().unwrap_or("")),
        );
        let routes: Vec<String> = t.routes.iter().map(|h| format!("{} {} {}", h.method, h.path, h.status)).collect();
        println!("      routes: {}", if routes.is_empty() { "none".into() } else { routes.join(", ") });
        println!("      usage: {} calls, {} prompt + {} completion tokens", t.usage.calls, t.usage.prompt_tokens, t.usage.completion_tokens);
        if let Some(calls) = &t.mock {
            for c in calls.iter().filter(|c| c.chosen.is_some()) {
                let ch = c.chosen.as_ref().expect("filtered");
                println!("      mock chose {} ({}) args {:?} of tools [{}]", ch.tool, ch.class, ch.arg_keys, c.tools.join(", "));
            }
        }
        if !t.pass {
            for (label, tail) in [("stdout", &t.stdout_tail), ("stderr", &t.stderr_tail)] {
                if !tail.is_empty() {
                    println!("      {label}:");
                    for l in tail.lines() {
                        println!("        {l}");
                    }
                }
            }
        }
        if let Some(w) = &t.workspace {
            println!("      workspace kept: {w}");
        }
    }
    println!("{}", if r.pass { "PASS" } else { "FAIL" });
}

/// `noo-gateway harness probe <args>` → the process exit code.
pub async fn main(args: &[String]) -> i32 {
    let a = match parse_args(args) {
        Ok(a) => a,
        Err(e) if e.is_empty() => {
            println!("{USAGE}");
            return 0;
        }
        Err(e) => {
            eprintln!("harness probe: {e}\n\n{USAGE}");
            return 2;
        }
    };
    match prepare_and_run(&a).await {
        Ok(r) => {
            if a.json {
                println!("{}", serde_json::to_string_pretty(&r).unwrap_or_else(|e| json!({"error": e.to_string()}).to_string()));
            } else {
                print_human(&r);
            }
            if r.pass { 0 } else { 1 }
        }
        Err(e) => {
            if a.json {
                println!("{}", json!({"kind": a.kind, "pass": false, "error": format!("{e:#}")}));
            } else {
                eprintln!("harness probe: {e:#}");
            }
            2
        }
    }
}

async fn prepare_and_run(a: &ProbeArgs) -> Result<Report> {
    let kind = crate::harness_kinds::get(&a.kind).ok_or_else(|| anyhow!("unknown kind {}", a.kind))?.clone();
    driver::validate_kind(&kind)?;
    // Real mode: the harness unit's own env file fills what is unset, BEFORE
    // the cluster client (which reads NOO_TLS_*) is first built.
    let mut env_file = None;
    if !a.mock_model {
        if let Ok(text) = std::fs::read_to_string(ENV_FILE) {
            for (k, v) in env_file_fill(&parse_env_file(&text), &|k| std::env::var(k).ok()) {
                std::env::set_var(k, v);
            }
            env_file = Some(ENV_FILE.to_string());
        }
    }
    let get = |k: &str| std::env::var(k).ok();
    let upstream = if a.mock_model { None } else { Some(resolve_backend(a, &get).map_err(|e| anyhow!(e))?) };
    let path = get("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
    let cli_name = kind.cli.clone().unwrap_or_else(|| kind.kind.clone());
    let cli = match &a.cli {
        Some(p) => p.clone(),
        None => find_on_path(&cli_name, &path).ok_or_else(|| anyhow!("{cli_name:?} is not on PATH; pass --cli <absolute path>"))?,
    };
    if !cli.is_file() {
        bail!("--cli {} is not a file", cli.display());
    }
    #[cfg(unix)]
    let run_as = decide_run_as(unsafe { libc::geteuid() }, a.run_as.as_deref(), &lookup_user)?;
    #[cfg(not(unix))]
    let run_as: Option<RunAsUser> = None;
    if let Some(u) = upstream.as_ref().filter(|u| coordinator::is_node_agent_url(&u.url)) {
        // As the harness does: ask the node's own agent whether it admits
        // this node's leaf without the bearer.
        crate::node_agent_auth::watch_own_agent(crate::tls::cluster_client(), u.url.clone()).await;
    }
    let parent_env: BTreeMap<String, String> = ["PATH", "LANG", "NOO_TLS_CA"].iter().filter_map(|k| get(k).map(|v| (k.to_string(), v))).collect();
    // Without --prompt, real mode runs what the node's profile says, and
    // without --context-tokens it tells the CLI the agent's model_context;
    // only asked of a node agent, and only for a kind that has a use for it.
    let wants_profile = a.prompt.is_none() && kind.launch_slim.is_some();
    let wants_window = a.context_tokens.is_none() && kind.launch.as_ref().is_some_and(driver::takes_context_window);
    let placement = match upstream.as_ref().filter(|u| (wants_profile || wants_window) && coordinator::is_node_agent_url(&u.url)) {
        Some(u) => match crate::harness_main::fetch_placement(&crate::tls::cluster_client(), &u.url).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "probe: could not read the node's placement; the full launch and the CLI's own window");
                None
            }
        },
        None => None,
    };
    let profile = placement.as_ref().and_then(HarnessProfile::from_placement);
    let (prompt, prompt_source) = resolve_claude_prompt(a.prompt, profile.as_ref());
    let (context_window, context_source) = resolve_context_window(a.context_tokens, placement.as_ref().and_then(model_context_of));
    let plan = Plan {
        kind, cli, upstream, tests: a.tests.clone(), timeout: Duration::from_secs(a.timeout), run_as, keep: a.keep, env_file, parent_env, prompt, prompt_source, context_window, context_source,
    };
    run_plan(&plan).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_parse_with_defaults_and_both_spellings() {
        let a = parse_args(&args(&["--kind", "copilot", "--mock-model", "--json"])).unwrap();
        assert_eq!((a.kind.as_str(), a.mock_model, a.json, a.timeout, a.keep), ("copilot", true, true, 300, false));
        assert_eq!(a.tests, [ProbeTest::Reply, ProbeTest::File]);
        let a = parse_args(&args(&["--kind=codex", "--cli=/opt/codex/bin/codex", "--test", "file", "--timeout=60", "--model-url", "http://127.0.0.1:8081/v1", "--model", "m", "--backend", "vllm", "--keep", "--run-as", "nobody"])).unwrap();
        assert_eq!(a.cli.as_deref(), Some(Path::new("/opt/codex/bin/codex")));
        assert_eq!((a.tests.as_slice(), a.timeout, a.backend.as_deref(), a.run_as.as_deref(), a.keep), (&[ProbeTest::File][..], 60, Some("vllm"), Some("nobody"), true));
        for (bad, why) in [
            (&["--mock-model"][..], "--kind is required"),
            (&["--kind", "noo"][..], "our own loop"),
            (&["--kind", "aider"][..], "unknown kind"),
            (&["--kind", "copilot", "--cli", "copilot"][..], "absolute"),
            (&["--kind", "copilot", "--test", "all"][..], "--test"),
            (&["--kind", "copilot", "--timeout", "0"][..], "--timeout"),
            (&["--kind", "copilot", "--backend", "anthropic"][..], "--backend"),
            (&["--kind", "copilot", "--mock-model", "--model-url", "http://x"][..], "--mock-model"),
            (&["--kind", "copilot", "--frobnicate"][..], "unknown argument"),
            (&["--kind"][..], "needs a value"),
        ] {
            let e = parse_args(&args(bad)).unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
        assert_eq!(parse_args(&args(&["--help"])).unwrap_err(), "", "help is not an error");
    }

    #[test]
    fn the_prompt_flag_picks_full_or_slim_and_only_where_a_slim_launch_exists() {
        assert_eq!(parse_args(&args(&["--kind", "claude-code"])).unwrap().prompt, None, "default: the profile, else full");
        assert_eq!(parse_args(&args(&["--kind", "claude-code", "--prompt", "slim"])).unwrap().prompt, Some(ClaudePrompt::Slim));
        assert_eq!(parse_args(&args(&["--kind=claude-code", "--prompt=full"])).unwrap().prompt, Some(ClaudePrompt::Full));
        assert_eq!(parse_args(&args(&["--kind", "copilot", "--prompt", "full"])).unwrap().prompt, Some(ClaudePrompt::Full), "full is every kind's");
        let e = parse_args(&args(&["--kind", "copilot", "--prompt", "slim"])).unwrap_err();
        assert!(e.contains("no slim launch"), "{e}");
        let e = parse_args(&args(&["--kind", "claude-code", "--prompt", "tiny"])).unwrap_err();
        assert!(e.contains("--prompt must be full or slim"), "{e}");
        assert!(parse_args(&args(&["--kind", "claude-code", "--prompt"])).unwrap_err().contains("needs a value"));
        assert!(USAGE.contains("--prompt <full|slim>"));
    }

    #[test]
    fn the_context_tokens_flag_is_a_positive_number() {
        assert_eq!(parse_args(&args(&["--kind", "claude-code"])).unwrap().context_tokens, None, "default: the agent's, else the CLI's");
        assert_eq!(parse_args(&args(&["--kind", "claude-code", "--context-tokens", "32768"])).unwrap().context_tokens, Some(32768));
        for bad in ["0", "-1", "32k"] {
            let e = parse_args(&args(&["--kind", "claude-code", "--context-tokens", bad])).unwrap_err();
            assert!(e.contains("--context-tokens must be"), "{bad}: {e}");
        }
        assert!(USAGE.contains("--context-tokens <n>"));
    }

    #[test]
    fn the_env_file_fills_only_what_is_unset_and_flags_win_over_both() {
        let file = parse_env_file(
            "# comment\nNODE_ID=awolf\nNOO_HARNESS_MODEL_URL=https://127.0.0.1:8081/v1\nNOO_HARNESS_MODEL=auto\nexport NOO_TLS_CERT=\"/etc/noo/pki/nodes/awolf.crt\"\nNOO_HARNESS_BACKEND='openai'\nNATS_NODE_USER=\nnot a line\n",
        );
        assert_eq!(file.len(), 6);
        assert_eq!(file[3], ("NOO_TLS_CERT".to_string(), "/etc/noo/pki/nodes/awolf.crt".to_string()));
        assert_eq!(file[4].1, "openai");
        let env: BTreeMap<&str, &str> = [("NOO_HARNESS_MODEL", "qwen-env"), ("NOO_HARNESS_BACKEND", "")].into_iter().collect();
        let get = |k: &str| env.get(k).map(|v| v.to_string());
        let fill = env_file_fill(&file, &get);
        let keys: Vec<&str> = fill.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"NOO_HARNESS_MODEL"), "the environment wins over the file");
        assert!(keys.contains(&"NOO_HARNESS_BACKEND"), "an empty variable is unset");
        assert!(keys.contains(&"NOO_HARNESS_MODEL_URL") && keys.contains(&"NOO_TLS_CERT"));

        let mut merged: BTreeMap<String, String> = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        merged.extend(fill);
        let mget = |k: &str| merged.get(k).cloned();
        let a = parse_args(&args(&["--kind", "copilot"])).unwrap();
        let b = resolve_backend(&a, &mget).unwrap();
        assert_eq!((b.url.as_str(), b.model.as_str(), b.backend_type.as_str(), b.api_format.as_str()), ("https://127.0.0.1:8081/v1", "qwen-env", "openai", "openai"));
        let a = parse_args(&args(&["--kind", "copilot", "--model-url", "http://127.0.0.1:11434", "--model", "llama", "--backend", "ollama"])).unwrap();
        let b = resolve_backend(&a, &mget).unwrap();
        assert_eq!((b.url.as_str(), b.model.as_str(), b.api_format.as_str()), ("http://127.0.0.1:11434", "llama", "ollama"), "flags win");
        assert!(resolve_backend(&parse_args(&args(&["--kind", "copilot"])).unwrap(), &|_| None).unwrap_err().contains("--model-url"));
    }

    #[cfg(unix)]
    #[test]
    fn root_runs_the_cli_as_an_unprivileged_user_and_never_as_uid_0() {
        let users = |n: &str| -> Result<RunAsUser> {
            match n {
                "nobody" => Ok(RunAsUser { user: n.into(), uid: 65534, gid: 65534 }),
                "root" | "toor" => Ok(RunAsUser { user: n.into(), uid: 0, gid: 0 }),
                "rbpai" => Ok(RunAsUser { user: n.into(), uid: 1000, gid: 1000 }),
                _ => bail!("no such user {n:?}"),
            }
        };
        assert_eq!(decide_run_as(0, None, &users).unwrap().unwrap().user, "nobody", "root defaults to nobody");
        assert_eq!(decide_run_as(0, Some("rbpai"), &users).unwrap().unwrap().uid, 1000);
        assert!(decide_run_as(0, Some("toor"), &users).unwrap_err().to_string().contains("uid 0"));
        assert!(decide_run_as(0, Some("ghost"), &users).is_err());
        assert_eq!(decide_run_as(1000, None, &users).unwrap(), None, "a user runs it as themselves");
        assert_eq!(decide_run_as(1000, Some("rbpai"), &users).unwrap(), None);
        assert!(decide_run_as(1000, Some("nobody"), &users).unwrap_err().to_string().contains("needs root"));
        assert!(lookup_user("root").map(|u| u.uid == 0).unwrap_or(true));
    }

    fn out(code: Option<i32>, stdout: &str, timed_out: bool) -> RunOutput {
        RunOutput { code, stdout: stdout.into(), stderr: "err line".into(), timed_out, stalled: None, elapsed: Duration::from_secs(2) }
    }

    fn hit(path: &str, status: u16) -> RouteHit {
        RouteHit { method: "POST".into(), path: path.into(), status }
    }

    #[test]
    fn the_verdict_and_the_file_decide() {
        let ok = [hit("/v1/messages", 200)];
        assert_eq!(judge(ProbeTest::Reply, &out(Some(0), "thinking\nNOO_RESULT: ok\n", false), &ok, None), (true, None));
        assert_eq!(judge(ProbeTest::File, &out(Some(0), "NOO_RESULT: done", false), &ok, Some("noomesh\n")), (true, None));
        let r = |t, o: RunOutput, routes: &[RouteHit], f: Option<&str>| judge(t, &o, routes, f).1.unwrap();
        assert!(r(ProbeTest::Reply, out(Some(0), "NOO_RESULT: ok", true), &ok, None).contains("timed out"));
        assert!(r(ProbeTest::Reply, out(Some(1), "NOO_RESULT: ok", false), &ok, None).starts_with("exit 1: err line"));
        assert!(r(ProbeTest::Reply, out(None, "", false), &ok, None).starts_with("killed"));
        assert!(r(ProbeTest::Reply, out(Some(0), "NOO_RESULT: nope", false), &ok, None).contains("wanted \"NOO_RESULT: ok\""));
        assert!(r(ProbeTest::Reply, out(Some(0), "hello", false), &[], None).contains("never called the translator"));
        assert!(r(ProbeTest::Reply, out(Some(0), "hello", false), &[hit("/v1/messages/count_tokens", 404)], None).contains("404 to POST /v1/messages/count_tokens"));
        assert!(r(ProbeTest::File, out(Some(0), "NOO_RESULT: done", false), &ok, None).contains("was not created"));
        assert!(r(ProbeTest::File, out(Some(0), "NOO_RESULT: done", false), &ok, Some("hello")).contains("contains \"hello\""));
        assert!(r(ProbeTest::File, out(Some(0), "NOO_RESULT: ok", false), &ok, Some("noomesh")).contains("wanted \"NOO_RESULT: done\""));
    }

    /// A stand-in "CLI": `sh -c` with the prompt as `$0`. It writes the
    /// file when the prompt asks for one, and answers with the verdict.
    fn fake_kind(script: &str) -> HarnessKind {
        serde_json::from_value(json!({
            "kind": "fake", "title": "fake", "wire": "OpenAI chat", "wires": ["llamacpp"], "runner": "noo-gateway", "cli": "sh",
            "lane": {"FAKE_LANE": "1"},
            "launch": {"command": ["sh", "-c", script, "{prompt}", "--mcp-config", "{mcp_config}"], "model_url_env": "FAKE_BASE_URL", "model_env": "FAKE_MODEL",
                       "mcp": "config-file", "model_url_suffix": "/v1", "api_key_env": "FAKE_API_KEY", "home_env": "FAKE_HOME"},
            "telemetry_off": {"FAKE_TELEMETRY": "0"},
        }))
        .unwrap()
    }

    fn plan(kind: HarnessKind, keep: bool) -> Plan {
        Plan {
            kind,
            cli: PathBuf::from("/bin/sh"),
            upstream: None,
            tests: vec![ProbeTest::Reply, ProbeTest::File],
            timeout: Duration::from_secs(30),
            run_as: None,
            keep,
            env_file: None,
            parent_env: [("PATH".to_string(), std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()))].into_iter().collect(),
            prompt: ClaudePrompt::Full,
            prompt_source: "default",
            context_window: None,
            context_source: "default",
        }
    }

    /// The window reaches a CLI that takes one, and the report says so
    /// (i147); a kind that takes none is told nothing.
    #[tokio::test]
    async fn the_probe_tells_the_cli_its_context_window() {
        let script = r#"[ "$FAKE_MAX_CONTEXT" = 4096 ] || { echo "NOO_FAILED: window ${FAKE_MAX_CONTEXT:-unset}"; exit 0; }; case "$0" in *probe.txt*) printf noomesh > probe.txt; echo "NOO_RESULT: done";; *) echo "NOO_RESULT: ok";; esac"#;
        let mut k = fake_kind(script);
        k.launch.as_mut().unwrap().context_window_env = Some("FAKE_MAX_CONTEXT".into());
        let mut p = plan(k.clone(), false);
        (p.context_window, p.context_source) = (Some(4096), "flag");
        let r = run_plan(&p).await.unwrap();
        assert!(r.pass, "{r:#?}");
        assert_eq!((r.context_window, r.context_source), (Some(4096), "flag"));
        let r = run_plan(&plan(k, false)).await.unwrap();
        assert_eq!(r.tests[0].verdict.as_deref(), Some("NOO_FAILED: window unset"), "{r:#?}");
        let mut p = plan(fake_kind(r#"echo "NOO_RESULT: ok""#), false);
        p.context_window = Some(4096);
        assert_eq!(run_plan(&p).await.unwrap().context_window, None, "a kind with no variable is told nothing");
    }

    /// `--prompt slim` runs the kind's slim launch with its system prompt
    /// file; full runs the launch. The report says which.
    #[tokio::test]
    async fn the_probe_runs_the_slim_launch_when_asked() {
        let mut k = fake_kind(r#"echo "NOO_FAILED: the full launch ran""#);
        let mut slim = k.launch.clone().unwrap();
        slim.command = vec!["sh".into(), "-c".into(), r#"[ -s "$0" ] || exit 7; case "$1" in *probe.txt*) printf noomesh > probe.txt; echo "NOO_RESULT: done";; *) echo "NOO_RESULT: ok";; esac"#.into(), "{system_prompt_file}".into(), "{prompt}".into()];
        slim.system_prompt_file = Some("noomesh-system-prompt.txt".into());
        k.launch_slim = Some(slim);
        let mut p = plan(k.clone(), false);
        p.prompt = ClaudePrompt::Slim;
        p.prompt_source = "flag";
        let r = run_plan(&p).await.unwrap();
        assert!(r.pass, "{r:#?}");
        assert_eq!((r.prompt, r.prompt_source), (ClaudePrompt::Slim, "flag"));
        let r = run_plan(&plan(k, false)).await.unwrap();
        assert!(!r.pass && r.tests[0].verdict.as_deref() == Some("NOO_FAILED: the full launch ran"), "{r:#?}");
        assert_eq!(r.prompt, ClaudePrompt::Full);
        assert_eq!(serde_json::to_value(&r).unwrap()["prompt"], "full");
    }

    #[tokio::test]
    async fn the_mock_probe_runs_a_cli_per_test_and_reports() {
        // No --mcp-config reached the CLI: $1/$2 would be the flag and a path.
        let script = r#"[ -n "$1" ] && { echo "NOO_FAILED: got MCP args $*"; exit 0; }; [ "$FAKE_MODEL" = noo-probe-mock ] || exit 9; [ -n "$FAKE_BASE_URL" ] || exit 8; case "$0" in *probe.txt*) printf noomesh > probe.txt; echo "NOO_RESULT: done";; *) echo "NOO_RESULT: ok";; esac"#;
        let r = run_plan(&plan(fake_kind(script), false)).await.unwrap();
        assert!(r.pass, "{r:#?}");
        assert_eq!(r.mode, "mock");
        assert_eq!(r.tests.len(), 2);
        assert_eq!((r.tests[0].test, r.tests[0].verdict.as_deref()), (ProbeTest::Reply, Some("NOO_RESULT: ok")));
        assert_eq!((r.tests[1].test, r.tests[1].verdict.as_deref()), (ProbeTest::File, Some("NOO_RESULT: done")));
        assert!(r.tests.iter().all(|t| t.exit_code == Some(0) && t.mock.is_some() && t.workspace.is_none()));
        assert!(r.cli_version.is_some(), "sh --version answers something, or its error line");
        let v = serde_json::to_value(&r).unwrap();
        for k in ["kind", "cli", "cli_version", "mode", "model", "tests", "pass"] {
            assert!(v.get(k).is_some(), "{k}");
        }
        for k in ["test", "pass", "reason", "exit_code", "seconds", "timed_out", "routes", "usage", "stdout_tail", "stderr_tail"] {
            assert!(v["tests"][0].get(k).is_some(), "{k}");
        }
    }

    #[tokio::test]
    async fn a_cli_that_writes_nothing_fails_the_file_test_with_a_reason_and_keep_keeps() {
        let r = run_plan(&plan(fake_kind(r#"echo "NOO_RESULT: done""#), true)).await.unwrap();
        assert!(!r.pass);
        assert!(!r.tests[0].pass, "the reply test wants ok");
        let file = &r.tests[1];
        assert!(!file.pass);
        let why = file.reason.as_deref().unwrap();
        assert!(why.contains("probe.txt was not created") && why.contains("never called the translator"), "{why}");
        let ws = PathBuf::from(file.workspace.as_deref().expect("kept"));
        assert!(ws.join("work").is_dir());
        let _ = std::fs::remove_dir_all(ws.parent().unwrap());
    }
}
