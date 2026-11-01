// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster gpu mode <node> [user|mesh]` — one verb for who has a node's
//! GPU (noomesh-internal i344b, PR 2).
//!
//! The mode is never stored: it is read from the node's GPU lease (the
//! agent's `gpu_contention`, on every heartbeat). No lease and vLLM serving
//! is `mesh`; a hold whose `purpose` is `user` is `user` (the operator's own
//! use of the GPU: VR, an experiment); a hold with a `workload` is a
//! reservation; any other hold is `held (manual)`.
//!
//! - `user` is a drain hold with `purpose: user` (the same call as `gpu
//!   hold`), then a wait for noomesh's GPU memory to reach 0, so `free_mb`
//!   is a measurement and not the last probe.
//! - `mesh` first checks the operator's own work has left the GPU (vLLM is
//!   stopped, so `foreign_mb` and `free_mb` are clean readings), then
//!   releases the lease with resume-now, then waits for proof that vLLM is
//!   running, healthy and warm.
//!
//! Both are compositions of the existing hold and release calls: no new
//! gateway route. Asking for the mode a node is already in changes nothing.
//! The wire is behind the [`Gateway`] trait so the sequences are tested
//! without a gateway.

use serde_json::{json, Value};

use crate::args::{ArgError, Args};
use crate::http::{get_json_try, request_status};
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

/// Seconds between two looks at the node record (the heartbeat is 30 s).
const POLL_SECS: u64 = 10;
/// How long `user` waits for noomesh's GPU memory to reach 0.
const FREE_CONFIRM_SECS: u64 = 60;
/// How long `mesh` waits for vLLM to be running, healthy and warm.
const PROOF_DEFAULT_SECS: u64 = 600;
/// The agent's own first yield rule (`NOO_GPU_YIELD_FOREIGN_MB`): more
/// foreign use than this pauses vLLM again after a minute.
const FOREIGN_LIMIT_MB: u64 = 2048;

// ── arguments ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Want {
    User,
    Mesh,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GpuModeArgs {
    pub node: String,
    pub mode: Option<Want>,
    pub timeout: Option<u64>,
    pub immediate: bool,
    pub wait: Option<u64>,
    pub no_wait: bool,
}

pub(crate) fn parse_gpu_mode(args: &[String]) -> Result<GpuModeArgs, ArgError> {
    parse_gpu_mode_with(&mut Args::new(args))
}

pub(crate) fn parse_gpu_mode_with(a: &mut Args) -> Result<GpuModeArgs, ArgError> {
    let timeout = a.number::<u64>(&["--timeout"])?;
    let immediate = a.flag(&["--immediate"]);
    let wait = a.number::<u64>(&["--wait"])?;
    let no_wait = a.flag(&["--no-wait"]);
    let mut p = a.positionals()?;
    if p.len() > 2 {
        return Err(ArgError::new(format!("unexpected argument `{}`", p[2])));
    }
    let mode = if p.len() == 2 { Some(p.remove(1)) } else { None };
    let node = p.pop().ok_or_else(|| ArgError::new("missing <node>"))?;
    let mode = match mode.as_deref() {
        None => None,
        Some("user") => Some(Want::User),
        Some("mesh") => Some(Want::Mesh),
        Some("voice") => return Err(ArgError::new("mode `voice` is not available yet; the modes are user and mesh")),
        Some(other) => return Err(ArgError::new(format!("unknown mode `{other}`; the modes are user and mesh"))),
    };
    if wait.is_some() && no_wait {
        return Err(ArgError::new("--wait and --no-wait cannot be used together"));
    }
    match mode {
        None if timeout.is_some() || immediate || wait.is_some() || no_wait => {
            return Err(ArgError::new("the flags change a mode; name one: user or mesh"));
        }
        Some(Want::User) if wait.is_some() || no_wait => {
            return Err(ArgError::new("--wait and --no-wait belong to mesh"));
        }
        Some(Want::Mesh) if timeout.is_some() || immediate => {
            return Err(ArgError::new("--timeout and --immediate belong to user"));
        }
        _ => {}
    }
    Ok(GpuModeArgs { node, mode, timeout, immediate, wait, no_wait })
}

// ── the mode, read from the lease ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mode {
    Mesh,
    User,
    /// A reservation: the lease names the workload it went to.
    Workload(String),
    /// A hold nobody labelled (a hand-typed `gpu hold`, or an agent that
    /// predates `purpose`).
    Manual,
    /// The automatic policy paused vLLM for work outside noomesh.
    Yielded,
    /// A hold is draining.
    Switching,
}

impl Mode {
    pub(crate) fn label(&self) -> String {
        match self {
            Mode::Mesh => "mesh".into(),
            Mode::User => "user".into(),
            Mode::Workload(w) => format!("workload {w}"),
            Mode::Manual => "held (manual)".into(),
            Mode::Yielded => "yielded (other GPU work)".into(),
            Mode::Switching => "switching".into(),
        }
    }
}

/// The mode a node's `gpu_contention` report says it is in.
pub(crate) fn lease_mode(gc: &Value) -> Mode {
    match gc["state"].as_str() {
        Some("draining") => Mode::Switching,
        Some("yielded") => Mode::Yielded,
        Some("held") => {
            let lease = &gc["lease"];
            match (lease["workload"].as_str().filter(|w| !w.is_empty()), lease["purpose"].as_str()) {
                (Some(w), _) => Mode::Workload(w.to_string()),
                (None, Some("user")) => Mode::User,
                _ => Mode::Manual,
            }
        }
        _ => Mode::Mesh,
    }
}

/// How long ago, for a status line: `45 s`, `12 min`, `3 h 5 min`, `2 d`.
pub(crate) fn age_text(secs: i64) -> String {
    match secs {
        s if s < 90 => format!("{} s", s.max(0)),
        s if s < 5400 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h {} min", s / 3600, (s % 3600) / 60),
        s => format!("{} d", s / 86_400),
    }
}

/// Seconds the lease has been held, when the report carries a usable
/// `since` and the clock is not before it.
pub(crate) fn lease_age(gc: &Value, now: i64) -> Option<i64> {
    let since = gc["lease"]["since"].as_str().or_else(|| gc["since"].as_str())?;
    let t = super::cluster_verify::parse_rfc3339_unix(since)?;
    Some(now - t).filter(|age| *age >= 0)
}

fn gb(mb: f64) -> String {
    format!("{:.1} GB", mb / 1024.0)
}

// ── vLLM's state, from the heartbeat ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Vllm {
    /// The agent lists a vllm container at all.
    pub reported: bool,
    pub running: bool,
    pub health: Option<String>,
    pub warmup: Option<String>,
    pub serving: Option<String>,
}

pub(crate) fn vllm_of(n: &Value) -> Vllm {
    let v = &n["backend_containers"]["vllm"];
    let text = |k: &str| v[k].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    Vllm {
        reported: v.is_object(),
        running: v["running"].as_bool().unwrap_or(false),
        health: text("health"),
        warmup: text("warmup"),
        serving: match &v["serving"] {
            Value::Bool(b) => Some(b.to_string()),
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        },
    }
}

impl Vllm {
    /// Running, healthy and warm: the engine is up, Docker's health is not
    /// `starting` or `unhealthy`, and the agent's warm request has ended
    /// (any result). An agent that reports neither key counts as done.
    pub(crate) fn ready(&self) -> bool {
        self.running
            && !matches!(self.health.as_deref(), Some("starting") | Some("unhealthy"))
            && matches!(self.warmup.as_deref(), None | Some("ok") | Some("failed") | Some("timeout") | Some("no_health"))
    }

    fn describe(&self) -> String {
        format!(
            "running {}, health {}, warmup {}{}",
            self.running,
            self.health.as_deref().unwrap_or("not reported"),
            self.warmup.as_deref().unwrap_or("not reported"),
            self.serving.as_deref().map(|s| format!(", serving {s}")).unwrap_or_default()
        )
    }
}

// ── the decision ─────────────────────────────────────────────────────────

/// Why the verb stopped. `remote` picks the exit code: a gateway or node
/// answer is a remote error, the verb's own refusals exit 1.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub kind: &'static str,
    pub msg: String,
    pub hint: Option<String>,
    pub remote: bool,
}

fn refuse(kind: &'static str, msg: String, hint: Option<String>) -> Refusal {
    Refusal { kind, msg, hint, remote: false }
}

#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// Nothing to write; the string says why.
    Already(String),
    /// The mode is mesh but vLLM is not warm yet: only wait for it.
    WaitWarm,
    Hold,
    Release { operation: String, generation: u64 },
    Refuse(Refusal),
}

/// The contention check for `mesh`: with vLLM stopped, `foreign_mb` and
/// `free_mb` read what the operator's own work uses. Some text when the GPU
/// is still in use, None when it is clear. Keys an older agent does not
/// send are not judged.
pub(crate) fn contention(gc: &Value) -> Option<String> {
    let mb = |k: &str| gc[k].as_f64();
    let foreign = mb("foreign_mb").unwrap_or(0.0);
    let need = mb("need_mb").unwrap_or(0.0);
    let mut why = Vec::new();
    if foreign > FOREIGN_LIMIT_MB as f64 {
        why.push(format!("foreign use {} is above the {} the node tolerates", gb(foreign), gb(FOREIGN_LIMIT_MB as f64)));
    }
    if let Some(free) = mb("free_mb").filter(|f| need > 0.0 && *f < need) {
        why.push(format!("{} free of {}, vllm needs {}", gb(free), gb(mb("total_mb").unwrap_or(0.0)), gb(need)));
    }
    if why.is_empty() {
        return None;
    }
    let mut text = why.join("; ");
    text.push_str(&format!(" ({})", gc["method"].as_str().unwrap_or("?")));
    if mb("unknown_mb").unwrap_or(0.0) > 0.0 {
        text.push_str(&format!(", unattributed {}", gb(mb("unknown_mb").unwrap_or(0.0))));
    }
    Some(text)
}

fn holder_text(gc: &Value) -> String {
    let reason = gc["lease"]["reason"].as_str().or_else(|| gc["reason"].as_str()).filter(|r| !r.is_empty());
    format!("{}{}", super::cluster_gpu::lease_holder(gc), reason.map(|r| format!(" ({r})")).unwrap_or_default())
}

fn release_line(id: &str, gc: &Value) -> String {
    match (gc["lease"]["operation_id"].as_str(), gc["lease"]["generation"].as_u64()) {
        (Some(op), Some(generation)) if !op.is_empty() => format!("noo cluster gpu release {id} --operation {op} --generation {generation}"),
        _ => format!("noo cluster gpu release {id}"),
    }
}

fn decide(n: &Value, want: Want) -> Plan {
    let id = n["id"].as_str().unwrap_or("?");
    let Some(gc) = n.get("gpu_contention").filter(|v| v.is_object()) else {
        return Plan::Refuse(refuse(
            "gpu_not_reported",
            format!("{id}: the node reports no GPU state (an older agent, or not a GPU node)"),
            Some(format!("noo cluster verify {id}")),
        ));
    };
    if let Some(status) = n["status"].as_str().filter(|s| *s != "online") {
        return Plan::Refuse(refuse(
            "node_not_reporting",
            format!("{id}: the node is {status}, not reporting; a mode change needs a live node"),
            Some(format!("noo cluster verify {id}")),
        ));
    }
    let mode = lease_mode(gc);
    let lease = &gc["lease"];
    let op = lease["operation_id"].as_str().unwrap_or("");
    match (want, &mode) {
        (_, Mode::Switching) => Plan::Refuse(refuse(
            "gpu_transition_in_progress",
            format!("{id}: a GPU hold by {} is draining right now", super::cluster_gpu::lease_holder(gc)),
            Some(format!("noo cluster verify {id}   # wait for the running hold or release to finish")),
        )),
        (Want::User, Mode::User) => Plan::Already(format!("{id}: already mode user")),
        (Want::User, Mode::Mesh) | (Want::User, Mode::Yielded) => {
            if gc["method"].as_str() == Some("not-measured") && gc["state"].as_str() != Some("yielded") {
                let why = match gc["unmeasured"].as_str() {
                    Some("driver-lost") => "the NVIDIA driver lost the GPU; reboot the node first".to_string(),
                    _ => "the node has no NVIDIA GPU noomesh can measure (none, or unified memory)".to_string(),
                };
                return Plan::Refuse(refuse("gpu_not_measurable", format!("{id}: {why}"), Some(format!("noo cluster verify {id}"))));
            }
            Plan::Hold
        }
        (Want::User, Mode::Manual) => Plan::Refuse(refuse(
            "gpu_held_by_other",
            format!("{id}: the GPU is already held by {}, not as mode user", holder_text(gc)),
            Some(format!("noo cluster gpu hold {id} --force   # take it over (audited); or release it first")),
        )),
        (Want::User, Mode::Workload(w)) | (Want::Mesh, Mode::Workload(w)) => Plan::Refuse(refuse(
            "gpu_held_by_other",
            format!("{id}: the GPU is reserved for {w} (reservation {op}); a running session is not cut by a mode switch"),
            Some(format!("noo cluster release {op}   # ends the reservation (the workload drains first)")),
        )),
        (Want::Mesh, Mode::Mesh) => {
            let v = vllm_of(n);
            if v.ready() {
                Plan::Already(format!("{id}: already mode mesh; vllm is running, healthy and warm"))
            } else if !v.reported {
                Plan::Already(format!("{id}: already mode mesh (no hold; the node reports no vllm container)"))
            } else {
                Plan::WaitWarm
            }
        }
        (Want::Mesh, Mode::Yielded) => Plan::Refuse(refuse(
            "gpu_yielded",
            format!("{id}: vllm was paused by the automatic policy for work outside noomesh; there is no hold to release, and vllm resumes once the GPU has stayed free"),
            Some(format!("noo cluster verify {id}   # the gpu row shows what is using it")),
        )),
        (Want::Mesh, Mode::Manual) => Plan::Refuse(refuse(
            "gpu_held_by_other",
            format!("{id}: the GPU is held by {}, not as mode user; the mode verb does not end another hold", holder_text(gc)),
            Some(format!("{}   # when the other work is done", release_line(id, gc))),
        )),
        (Want::Mesh, Mode::User) => {
            if let Some(why) = contention(gc) {
                return Plan::Refuse(refuse(
                    "gpu_busy_by_other_work",
                    format!("{id}: the GPU is still in use by other work: {why}; vllm would start into it and be paused again after a minute"),
                    Some(format!("noo cluster gpu mode {id} mesh --wait 300   # wait for it to leave, then switch")),
                ));
            }
            match (lease["operation_id"].as_str().filter(|o| !o.is_empty()), lease["generation"].as_u64()) {
                (Some(o), Some(generation)) => Plan::Release { operation: o.to_string(), generation },
                _ => Plan::Refuse(refuse(
                    "gpu_hold_refused",
                    format!("{id}: the node's lease carries no operation id and generation to release"),
                    Some(format!("noo cluster verify {id}")),
                )),
            }
        }
    }
}

// ── the wire ─────────────────────────────────────────────────────────────

pub(crate) trait Gateway {
    /// The node's record from `GET /api/cluster/nodes`.
    fn node(&mut self, node: &str) -> Result<Value, String>;
    fn hold(&mut self, node: &str, body: &Value) -> Result<Value, (u16, String)>;
    fn release(&mut self, node: &str, body: &Value) -> Result<Value, (u16, String)>;
    fn sleep(&mut self, secs: u64);
    fn now(&self) -> i64;
    /// A progress line for the operator (silent under --json).
    fn say(&mut self, line: &str);
}

/// What a mode change (or a read) came to.
#[derive(Debug)]
pub(crate) struct Outcome {
    pub node: String,
    pub previous: Mode,
    pub mode: Mode,
    pub changed: bool,
    /// The last node record seen.
    pub record: Value,
    pub steps: Vec<String>,
    pub elapsed_secs: i64,
    /// `user`: noomesh's GPU memory reached 0. None for other results.
    pub free_confirmed: Option<bool>,
    /// `mesh`: vLLM was running, healthy and warm. None when not waited for.
    pub warm: Option<bool>,
    /// Seconds from the write to the proof, when there was one.
    pub proof_secs: Option<u64>,
    pub note: Option<String>,
}

impl Outcome {
    fn new(node: &str, mode: Mode, record: Value) -> Outcome {
        Outcome {
            node: node.to_string(),
            previous: mode.clone(),
            mode,
            changed: false,
            record,
            steps: Vec::new(),
            elapsed_secs: 0,
            free_confirmed: None,
            warm: None,
            proof_secs: None,
            note: None,
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        let gc = &self.record["gpu_contention"];
        let lease = &gc["lease"];
        let v = vllm_of(&self.record);
        let mut out = json!({
            "node": self.node,
            "mode": self.mode.label(),
            "previous": self.previous.label(),
            "changed": self.changed,
            "gpu": {"total_mb": gc["total_mb"], "free_mb": gc["free_mb"], "foreign_mb": gc["foreign_mb"], "noomesh_mb": gc["noomesh_mb"]},
            "vllm": {"running": v.running, "health": v.health, "warmup": v.warmup, "serving": v.serving},
            "elapsed_secs": self.elapsed_secs,
            "steps": self.steps,
        });
        if lease.is_object() {
            out["lease"] = json!({"operation_id": lease["operation_id"], "generation": lease["generation"], "since": lease["since"]});
        }
        if let Some(c) = self.free_confirmed {
            out["gpu_free_confirmed"] = json!(c);
        }
        if let Some(w) = self.warm {
            out["warm"] = json!(w);
        }
        if let Some(p) = self.proof_secs {
            out["proof_secs"] = json!(p);
        }
        if let Some(n) = &self.note {
            out["note"] = json!(n);
        }
        out
    }
}

/// A gateway refusal, with the mode verb's own remedy for a drain that
/// timed out.
fn gateway_refusal(node: &str, op: &str, status: u16, text: &str) -> Refusal {
    let msg = serde_json::from_str::<Value>(text).ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_else(|| text.trim().to_string());
    if status != 409 {
        return Refusal { kind: "remote_error", msg: format!("gateway returned {status} for the GPU {op} on {node}: {msg}"), hint: None, remote: true };
    }
    let (kind, hint) = super::cluster_gpu::refusal_hint(node, op, &msg);
    let hint = if kind == "gpu_drain_timeout" {
        format!("noo cluster gpu mode {node} user --timeout 600   # wait longer; --immediate cuts what runs (emergency)")
    } else {
        hint
    };
    Refusal { kind, msg: format!("{node}: GPU {op} refused — {msg}"), hint: Some(hint), remote: true }
}

fn node_refusal(node: &str, e: &str) -> Refusal {
    Refusal { kind: "remote_error", msg: format!("could not read {node} from the gateway: {e}"), hint: Some("noo cluster status".into()), remote: true }
}

fn mode_of_record(rec: &Value) -> Mode {
    rec.get("gpu_contention").filter(|v| v.is_object()).map(lease_mode).unwrap_or(Mode::Mesh)
}

/// `noo cluster gpu mode <node>`: the current mode, read-only.
pub(crate) fn show(gw: &mut impl Gateway, node: &str) -> Result<Outcome, Refusal> {
    let rec = gw.node(node).map_err(|e| node_refusal(node, &e))?;
    Ok(Outcome::new(node, mode_of_record(&rec), rec))
}

/// Switch the node to the wanted mode (a no-op when it is already there).
pub(crate) fn run(gw: &mut impl Gateway, a: &GpuModeArgs, want: Want) -> Result<Outcome, Refusal> {
    let node = a.node.as_str();
    let start = gw.now();
    let mut rec = gw.node(node).map_err(|e| node_refusal(node, &e))?;
    // `mesh --wait`: while the operator's own work still uses the GPU, look
    // again until it leaves or the budget is gone.
    let budget = if want == Want::Mesh { a.wait.unwrap_or(0) } else { 0 };
    let mut waited = 0u64;
    let plan = loop {
        let plan = decide(&rec, want);
        let busy = matches!(&plan, Plan::Refuse(r) if r.kind == "gpu_busy_by_other_work");
        if !busy || waited >= budget {
            break plan;
        }
        gw.say(&format!("{node}: the GPU is still in use by other work; looking again in {POLL_SECS} s ({waited} of {budget} s)"));
        gw.sleep(POLL_SECS);
        waited += POLL_SECS;
        if let Ok(next) = gw.node(node) {
            rec = next;
        }
    };
    let mut out = Outcome::new(node, mode_of_record(&rec), rec.clone());
    let mut steps = Vec::new();
    match plan {
        Plan::Refuse(r) => return Err(r),
        Plan::Already(note) => {
            out.note = Some(note);
            return Ok(out);
        }
        Plan::WaitWarm => {
            steps.push("vllm is not warm yet; no write needed".to_string());
            if a.no_wait {
                out.note = Some(format!("{node}: mode mesh; vllm is not warm yet and --no-wait was given ({})", vllm_of(&rec).describe()));
            } else {
                wait_warm(gw, a, &mut out, &mut steps)?;
            }
        }
        Plan::Hold => {
            let timeout = a.timeout.unwrap_or(120).clamp(1, 900);
            let how = if a.immediate { "immediate" } else { "drain" };
            if a.immediate {
                gw.say(&format!("{node}: stopping its GPU backends now (--immediate: requests in flight are cut)"));
            } else {
                gw.say(&format!("{node}: draining its GPU backends (nothing new routed there; up to {timeout} s for what runs to finish)"));
            }
            let body = json!({
                "reason": "user",
                "purpose": "user",
                "operation_id": super::cluster_gpu::new_operation_id(),
                "mode": how,
                "timeout_secs": timeout,
                "force": false,
            });
            let resp = gw.hold(node, &body).map_err(|(s, t)| gateway_refusal(node, "hold", s, &t))?;
            steps.push(format!("hold (purpose user, {how}) accepted"));
            let held_at = gw.now();
            // The hold's own answer carries the last probe, up to 15 s old,
            // and the next heartbeat up to 30 s later. Free is proven when
            // noomesh's own GPU memory reads 0.
            let mut cur = json!({"id": node, "gpu_contention": resp["gpu_contention"].clone()});
            let mut waited = 0u64;
            let confirmed = loop {
                if let Ok(next) = gw.node(node) {
                    cur = next;
                }
                if cur["gpu_contention"]["noomesh_mb"].as_f64() == Some(0.0) {
                    break true;
                }
                if waited >= FREE_CONFIRM_SECS {
                    break false;
                }
                gw.sleep(POLL_SECS);
                waited += POLL_SECS;
            };
            steps.push(if confirmed {
                "noomesh's GPU memory reached 0".to_string()
            } else {
                format!("noomesh's GPU memory did not reach 0 in {FREE_CONFIRM_SECS} s")
            });
            out.mode = Mode::User;
            out.changed = true;
            out.free_confirmed = Some(confirmed);
            out.proof_secs = Some((gw.now() - held_at).max(0) as u64);
            out.record = cur;
        }
        Plan::Release { operation, generation } => {
            let free = gb(rec["gpu_contention"]["free_mb"].as_f64().unwrap_or(0.0));
            gw.say(&format!("{node}: the GPU is clear ({free} free); releasing the hold, vllm resumes now"));
            let body = json!({"operation_id": operation, "generation": generation, "force": false, "resume": "now"});
            let resp = gw.release(node, &body).map_err(|(s, t)| gateway_refusal(node, "release", s, &t))?;
            steps.push("contention check passed".to_string());
            steps.push("released with resume-now".to_string());
            out.mode = Mode::Mesh;
            out.changed = true;
            out.record = json!({"id": node, "gpu_contention": resp["gpu_contention"].clone(), "backend_containers": rec["backend_containers"].clone()});
            if a.no_wait {
                out.note = Some(format!("{node}: released; not waiting for vllm (--no-wait)"));
            } else {
                wait_warm(gw, a, &mut out, &mut steps)?;
            }
        }
    }
    out.steps = steps;
    out.elapsed_secs = (gw.now() - start).max(0);
    Ok(out)
}

/// Poll until vLLM is running, healthy and warm. Running out of time is
/// `needs_attention`: the mode is mesh either way (the lease is gone) and
/// nothing is rolled back.
fn wait_warm(gw: &mut impl Gateway, a: &GpuModeArgs, out: &mut Outcome, steps: &mut Vec<String>) -> Result<(), Refusal> {
    let node = a.node.as_str();
    let budget = a.wait.unwrap_or(PROOF_DEFAULT_SECS);
    let began = gw.now();
    let mut waited = 0u64;
    let mut last = vllm_of(&out.record);
    loop {
        match gw.node(node) {
            Ok(rec) => {
                last = vllm_of(&rec);
                out.record = rec;
            }
            Err(e) => gw.say(&format!("{node}: could not read the node ({e}); trying again")),
        }
        if last.ready() {
            out.warm = Some(true);
            out.proof_secs = Some((gw.now() - began).max(0) as u64);
            steps.push(format!("vllm {}", last.describe()));
            return Ok(());
        }
        if waited >= budget {
            out.warm = Some(false);
            return Err(refuse(
                "needs_attention",
                format!(
                    "{node}: the hold is released (mode mesh) but vllm is not running, healthy and warm after {budget} s: {}. Nothing was rolled back; a cold load can take longer",
                    last.describe()
                ),
                Some(format!("noo cluster verify {node}   # shows the container's health; run the mode verb again to keep waiting")),
            ));
        }
        gw.say(&format!("{node}: waiting for vllm ({}) {waited} of {budget} s", last.describe()));
        gw.sleep(POLL_SECS);
        waited += POLL_SECS;
    }
}

// ── the real gateway ─────────────────────────────────────────────────────

struct Live<'a> {
    g: &'a Globals,
}

impl Gateway for Live<'_> {
    fn node(&mut self, node: &str) -> Result<Value, String> {
        let body = get_json_try(self.g, "/api/cluster/nodes", true, 10)?;
        body["nodes"].as_array()
            .and_then(|a| a.iter().find(|n| n["id"].as_str() == Some(node)))
            .cloned()
            .ok_or_else(|| format!("no node named {node} in the cluster"))
    }

    fn hold(&mut self, node: &str, body: &Value) -> Result<Value, (u16, String)> {
        let timeout = body["timeout_secs"].as_u64().unwrap_or(120);
        request_status(self.g, "POST", &format!("/api/cluster/nodes/{}/gpu/hold", super::urlencode(node)), Some(body), true, timeout + 90)
    }

    fn release(&mut self, node: &str, body: &Value) -> Result<Value, (u16, String)> {
        request_status(self.g, "POST", &format!("/api/cluster/nodes/{}/gpu/release", super::urlencode(node)), Some(body), true, 90)
    }

    fn sleep(&mut self, secs: u64) {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }

    fn now(&self) -> i64 {
        crate::host_exec::now_unix()
    }

    fn say(&mut self, line: &str) {
        if !self.g.json {
            println!("{}", ui::muted(line));
        }
    }
}

/// `noo cluster gpu mode <node> [user|mesh] [--timeout <secs>] [--immediate] [--wait <secs>] [--no-wait]`
pub fn cluster_gpu_mode(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let a = parse_gpu_mode(args)?;
    let mut gw = Live { g };
    let result = match a.mode {
        None => show(&mut gw, &a.node),
        Some(want) => run(&mut gw, &a, want),
    };
    let out = match result {
        Ok(o) => o,
        Err(r) => fail(g.json, if r.remote { ExitCode::RemoteError } else { ExitCode::Generic }, r.kind, &r.msg, r.hint.as_deref()),
    };
    if g.json {
        println!("{}", out.to_json());
    } else {
        print_outcome(&out, a.mode.is_none(), gw.now());
    }
    Ok(0)
}

fn print_outcome(out: &Outcome, read_only: bool, now: i64) {
    let node = out.node.as_str();
    let gc = &out.record["gpu_contention"];
    if read_only {
        let age = lease_age(gc, now).map(|s| format!(", held {}", age_text(s))).unwrap_or_default();
        ui::done(&format!("{node}: mode {}{age}", out.mode.label()));
        let v = vllm_of(&out.record);
        if out.mode == Mode::Mesh && v.reported {
            println!("{}", ui::muted(&format!("vllm {}", v.describe())));
        }
        if gc["free_mb"].is_number() {
            println!("{}", ui::muted(&format!("GPU free {} of {}", gb(gc["free_mb"].as_f64().unwrap_or(0.0)), gb(gc["total_mb"].as_f64().unwrap_or(0.0)))));
        }
        return;
    }
    if let Some(note) = &out.note {
        ui::done(note);
    }
    if !out.changed {
        return;
    }
    match out.mode {
        Mode::User => {
            ui::done(&format!("{node}: mode user; {} paused, chat for the mesh goes to other nodes", super::cluster_gpu::paused_list(gc)));
            let free = gb(gc["free_mb"].as_f64().unwrap_or(0.0));
            if out.free_confirmed == Some(true) {
                ui::done(&format!(
                    "GPU free: {free} of {} (noomesh uses 0, measured {} s after the stop)",
                    gb(gc["total_mb"].as_f64().unwrap_or(0.0)),
                    out.proof_secs.unwrap_or(0)
                ));
            } else {
                ui::warned(&format!(
                    "GPU not confirmed free after {FREE_CONFIRM_SECS} s: noomesh still reports {} in use, {free} free; the hold is on",
                    gb(gc["noomesh_mb"].as_f64().unwrap_or(0.0))
                ));
            }
            let lease = &gc["lease"];
            if let (Some(op), Some(generation)) = (lease["operation_id"].as_str(), lease["generation"].as_u64()) {
                println!("{}", ui::muted(&format!("lease: operation {op}, generation {generation}")));
            }
            let mesh = format!("noo cluster gpu mode {node} mesh");
            ui::guide(&[(mesh.as_str(), "give the GPU back to vllm: checks it is free, releases, waits until vllm is warm")]);
        }
        Mode::Mesh if out.warm == Some(true) => {
            let v = vllm_of(&out.record);
            ui::done(&format!(
                "{node}: mode mesh; vllm {} {} s after the release; chat routes to {node} again",
                v.describe(),
                out.proof_secs.unwrap_or(0)
            ));
        }
        Mode::Mesh => {
            ui::done(&format!("{node}: mode mesh; the hold is released and vllm is starting"));
            let verify = format!("noo cluster verify {node}");
            ui::guide(&[(verify.as_str(), "the gpu row and the vllm container show when it is warm")]);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn args(node: &str, mode: Want) -> GpuModeArgs {
        GpuModeArgs { node: node.into(), mode: Some(mode), timeout: None, immediate: false, wait: None, no_wait: false }
    }

    /// A node record: `gc` is its gpu_contention, `vllm` its vllm container.
    fn node(gc: Value, vllm: Value) -> Value {
        json!({"id": "awolf", "status": "online", "gpu_contention": gc, "backend_containers": {"vllm": vllm}})
    }

    fn warm() -> Value {
        json!({"running": true, "health": "healthy", "warmup": "ok"})
    }

    fn starting() -> Value {
        json!({"running": true, "health": "starting", "warmup": "running"})
    }

    fn stopped() -> Value {
        json!({"running": false})
    }

    fn free_gc() -> Value {
        json!({"state": "free", "method": "memory-accounting", "total_mb": 16384, "free_mb": 15000, "foreign_mb": 0, "noomesh_mb": 11500, "need_mb": 11500})
    }

    fn user_gc(free_mb: u64, foreign_mb: u64) -> Value {
        json!({"state": "held", "method": "memory-accounting", "total_mb": 16384, "free_mb": free_mb, "foreign_mb": foreign_mb,
            "noomesh_mb": 0, "need_mb": 11500, "paused_backends": ["vllm"],
            "lease": {"owner": "rbwolf", "operation_id": "op-7", "generation": 4, "mode": "drain", "reason": "user", "purpose": "user",
                "since": "2026-11-01T10:00:00Z"}})
    }

    /// A scripted gateway. `before` and `after` are the records the next
    /// `node()` calls return (once the write has happened, `after` is
    /// used); when a queue is empty the last record repeats.
    #[derive(Default)]
    struct Fake {
        node: Value,
        before: VecDeque<Value>,
        after: VecDeque<Value>,
        on_hold: Value,
        on_release: Value,
        hold_err: Option<(u16, String)>,
        release_err: Option<(u16, String)>,
        wrote: bool,
        calls: Vec<String>,
        bodies: Vec<Value>,
        said: Vec<String>,
        clock: i64,
    }

    impl Gateway for Fake {
        fn node(&mut self, _node: &str) -> Result<Value, String> {
            let queue = if self.wrote { &mut self.after } else { &mut self.before };
            if let Some(next) = queue.pop_front() {
                self.node = next;
            }
            Ok(self.node.clone())
        }
        fn hold(&mut self, _node: &str, body: &Value) -> Result<Value, (u16, String)> {
            self.calls.push("hold".into());
            self.bodies.push(body.clone());
            if let Some(e) = self.hold_err.clone() {
                return Err(e);
            }
            self.wrote = true;
            self.node = self.on_hold.clone();
            Ok(json!({"gpu_contention": self.node["gpu_contention"].clone()}))
        }
        fn release(&mut self, _node: &str, body: &Value) -> Result<Value, (u16, String)> {
            self.calls.push("release".into());
            self.bodies.push(body.clone());
            if let Some(e) = self.release_err.clone() {
                return Err(e);
            }
            self.wrote = true;
            self.node = self.on_release.clone();
            Ok(json!({"gpu_contention": self.node["gpu_contention"].clone()}))
        }
        fn sleep(&mut self, secs: u64) {
            self.clock += secs as i64;
        }
        fn now(&self) -> i64 {
            self.clock
        }
        fn say(&mut self, line: &str) {
            self.said.push(line.to_string());
        }
    }

    #[test]
    fn mode_is_read_from_each_lease_shape() {
        assert_eq!(lease_mode(&json!({"state": "free"})), Mode::Mesh);
        assert_eq!(lease_mode(&json!({"state": "shared", "foreign_mb": 3000})), Mode::Mesh);
        assert_eq!(lease_mode(&user_gc(15000, 0)), Mode::User);
        let reservation = json!({"state": "held", "lease": {"operation_id": "r-1", "workload": "rhaddon/worker", "purpose": ""}});
        assert_eq!(lease_mode(&reservation), Mode::Workload("rhaddon/worker".into()));
        let manual = json!({"state": "held", "reason": "voice", "lease": {"owner": "rbwolf", "operation_id": "op-1", "generation": 2}});
        assert_eq!(lease_mode(&manual), Mode::Manual);
        assert_eq!(lease_mode(&json!({"state": "held"})), Mode::Manual, "an agent with no lease at all");
        let old = json!({"state": "held", "lease": {"operation_id": "op-1", "reason": "user"}});
        assert_eq!(lease_mode(&old), Mode::Manual, "a reason of `user` is not a purpose");
        assert_eq!(lease_mode(&json!({"state": "yielded"})), Mode::Yielded);
        assert_eq!(lease_mode(&json!({"state": "draining", "lease": {"purpose": "user"}})), Mode::Switching);
        assert_eq!(lease_mode(&json!({})), Mode::Mesh);
        assert_eq!(Mode::Workload("a/b".into()).label(), "workload a/b");
        assert_eq!(Mode::Manual.label(), "held (manual)");
    }

    #[test]
    fn ages_read_plainly() {
        assert_eq!(age_text(45), "45 s");
        assert_eq!(age_text(600), "10 min");
        assert_eq!(age_text(7500), "2 h 5 min");
        assert_eq!(age_text(300_000), "3 d");
        let gc = user_gc(15000, 0);
        let since = super::super::cluster_verify::parse_rfc3339_unix("2026-11-01T10:00:00Z").unwrap();
        assert_eq!(lease_age(&gc, since + 7500), Some(7500));
        assert_eq!(lease_age(&gc, since - 5), None, "a clock before the lease reads no age");
        assert_eq!(lease_age(&json!({"state": "held"}), since), None);
    }

    #[test]
    fn vllm_is_ready_only_when_running_healthy_and_warm() {
        assert!(vllm_of(&node(free_gc(), warm())).ready());
        assert!(!vllm_of(&node(free_gc(), starting())).ready());
        let warming = json!({"running": true, "health": "healthy", "warmup": "running"});
        assert!(!vllm_of(&node(free_gc(), warming)).ready());
        let unhealthy = json!({"running": true, "health": "unhealthy", "warmup": "ok"});
        assert!(!vllm_of(&node(free_gc(), unhealthy)).ready());
        assert!(!vllm_of(&node(free_gc(), stopped())).ready());
        for done in ["ok", "failed", "timeout", "no_health"] {
            assert!(vllm_of(&node(free_gc(), json!({"running": true, "health": "healthy", "warmup": done}))).ready(), "{done}");
        }
        assert!(vllm_of(&node(free_gc(), json!({"running": true}))).ready(), "an agent that reports neither key");
        assert!(!vllm_of(&json!({"id": "x"})).reported);
        assert_eq!(vllm_of(&node(free_gc(), json!({"running": true, "serving": false}))).serving.as_deref(), Some("false"));
    }

    #[test]
    fn contention_refuses_low_free_and_high_foreign() {
        assert_eq!(contention(&user_gc(15000, 0)), None);
        assert_eq!(contention(&user_gc(11500, 2048)), None, "exactly at both limits is clear");
        let low = contention(&user_gc(4000, 1000)).unwrap();
        assert!(low.contains("3.9 GB free of 16.0 GB, vllm needs 11.2 GB"), "{low}");
        let high = contention(&user_gc(15000, 6000)).unwrap();
        assert!(high.contains("foreign use 5.9 GB is above the 2.0 GB"), "{high}");
        // An older agent without the keys is not judged.
        assert_eq!(contention(&json!({"state": "held"})), None);
        let unknown = contention(&json!({"free_mb": 100, "need_mb": 11500, "total_mb": 16384, "method": "nvidia-smi-unattributed", "unknown_mb": 2048})).unwrap();
        assert!(unknown.contains("unattributed 2.0 GB") && unknown.contains("(nvidia-smi-unattributed)"), "{unknown}");
    }

    #[test]
    fn mesh_refuses_while_the_operators_work_uses_the_gpu() {
        for (free, foreign) in [(4000, 1000), (15000, 6000)] {
            let mut f = Fake { node: node(user_gc(free, foreign), stopped()), ..Default::default() };
            let r = run(&mut f, &args("awolf", Want::Mesh), Want::Mesh).unwrap_err();
            assert_eq!(r.kind, "gpu_busy_by_other_work", "{r:?}");
            assert!(!r.remote, "the verb's own refusal exits 1");
            assert!(r.msg.contains("still in use by other work"), "{}", r.msg);
            assert!(r.hint.as_deref().unwrap().starts_with("noo cluster gpu mode awolf mesh --wait 300"));
            assert!(f.calls.is_empty(), "no write when the GPU is busy: {:?}", f.calls);
        }
    }

    #[test]
    fn mesh_wait_polls_the_check_then_releases() {
        let busy = || node(user_gc(4000, 6000), stopped());
        let mut f = Fake { node: busy(), on_release: node(free_gc(), warm()), ..Default::default() };
        // The first look is busy; two more looks stay busy, the next is clear.
        f.before = VecDeque::from([busy(), busy(), busy(), node(user_gc(15000, 0), stopped())]);
        let mut a = args("awolf", Want::Mesh);
        a.wait = Some(60);
        let out = run(&mut f, &a, Want::Mesh).unwrap();
        assert_eq!(f.calls, vec!["release".to_string()], "released once the check passed");
        assert_eq!(f.said.iter().filter(|s| s.contains("looking again")).count(), 3, "{:?}", f.said);
        let rel = &f.bodies[0];
        assert_eq!(rel["operation_id"], "op-7");
        assert_eq!(rel["generation"], 4);
        assert_eq!(rel["resume"], "now");
        assert_eq!(rel["force"], false);
        assert_eq!(out.warm, Some(true));
        // A budget that runs out while the GPU is still busy is the refusal.
        let mut f = Fake { node: busy(), ..Default::default() };
        let mut a = args("awolf", Want::Mesh);
        a.wait = Some(20);
        let r = run(&mut f, &a, Want::Mesh).unwrap_err();
        assert_eq!(r.kind, "gpu_busy_by_other_work");
        assert_eq!(f.clock, 20);
        assert!(f.calls.is_empty());
    }

    #[test]
    fn mesh_waits_for_proof_then_reports_warm() {
        let mut f = Fake { node: node(user_gc(15000, 0), stopped()), on_release: node(free_gc(), starting()), ..Default::default() };
        f.after = VecDeque::from([node(free_gc(), starting()), node(free_gc(), starting()), node(free_gc(), warm())]);
        let out = run(&mut f, &args("awolf", Want::Mesh), Want::Mesh).unwrap();
        assert!(out.changed);
        assert_eq!(out.previous, Mode::User);
        assert_eq!(out.mode, Mode::Mesh);
        assert_eq!(out.warm, Some(true));
        assert_eq!(out.proof_secs, Some(20), "two polls of ten seconds");
        assert_eq!(f.calls, vec!["release".to_string()]);
        let j = out.to_json();
        assert_eq!(j["mode"], "mesh");
        assert_eq!(j["previous"], "user");
        assert_eq!(j["vllm"]["warmup"], "ok");
        assert_eq!(j["warm"], true);
        assert_eq!(j["elapsed_secs"], 20);
    }

    #[test]
    fn mesh_no_wait_returns_after_the_release() {
        let mut f = Fake { node: node(user_gc(15000, 0), stopped()), on_release: node(free_gc(), starting()), ..Default::default() };
        let mut a = args("awolf", Want::Mesh);
        a.no_wait = true;
        let out = run(&mut f, &a, Want::Mesh).unwrap();
        assert!(out.changed);
        assert_eq!(out.warm, None);
        assert_eq!(f.clock, 0, "no polling");
        assert!(out.note.unwrap().contains("--no-wait"));
    }

    #[test]
    fn mesh_that_never_warms_is_needs_attention() {
        let mut f = Fake { node: node(user_gc(15000, 0), stopped()), on_release: node(free_gc(), starting()), ..Default::default() };
        let mut a = args("awolf", Want::Mesh);
        a.wait = Some(30);
        let r = run(&mut f, &a, Want::Mesh).unwrap_err();
        assert_eq!(r.kind, "needs_attention");
        assert!(r.msg.contains("after 30 s") && r.msg.contains("Nothing was rolled back"), "{}", r.msg);
        assert_eq!(f.clock, 30);
        assert!(r.hint.unwrap().starts_with("noo cluster verify awolf"));
    }

    #[test]
    fn repeats_are_idempotent() {
        // mesh on a node that is already mesh and warm: no write.
        let mut f = Fake { node: node(free_gc(), warm()), ..Default::default() };
        let out = run(&mut f, &args("awolf", Want::Mesh), Want::Mesh).unwrap();
        assert!(!out.changed);
        assert!(out.note.unwrap().contains("already mode mesh"));
        assert!(f.calls.is_empty());
        // user on a node already user: no write.
        let mut f = Fake { node: node(user_gc(15000, 0), stopped()), ..Default::default() };
        let out = run(&mut f, &args("awolf", Want::User), Want::User).unwrap();
        assert!(!out.changed);
        assert_eq!(out.mode, Mode::User);
        assert!(f.calls.is_empty());
        // mesh while vllm is still warming after an earlier release: only waits.
        let warming = || node(free_gc(), json!({"running": true, "health": "healthy", "warmup": "running"}));
        let mut f = Fake { node: warming(), ..Default::default() };
        f.before = VecDeque::from([warming(), warming(), node(free_gc(), warm())]);
        let out = run(&mut f, &args("awolf", Want::Mesh), Want::Mesh).unwrap();
        assert_eq!(out.warm, Some(true));
        assert!(!out.changed);
        assert!(f.calls.is_empty(), "a repeat never releases again");
        // mesh on a node with no vllm container reported.
        let mut f = Fake { node: json!({"id": "awolf", "status": "online", "gpu_contention": {"state": "free"}}), ..Default::default() };
        assert!(!run(&mut f, &args("awolf", Want::Mesh), Want::Mesh).unwrap().changed);
    }

    #[test]
    fn user_holds_with_the_purpose_and_waits_for_the_gpu_to_be_free() {
        let drained = |noomesh: u64| {
            let mut gc = user_gc(15000, 0);
            gc["noomesh_mb"] = json!(noomesh);
            node(gc, stopped())
        };
        let mut f = Fake { node: node(free_gc(), warm()), on_hold: drained(11500), ..Default::default() };
        f.after = VecDeque::from([drained(11500), drained(11500), drained(0)]);
        let mut a = args("awolf", Want::User);
        a.timeout = Some(300);
        let out = run(&mut f, &a, Want::User).unwrap();
        assert_eq!(f.calls, vec!["hold".to_string()]);
        let body = &f.bodies[0];
        assert_eq!(body["purpose"], "user");
        assert_eq!(body["reason"], "user");
        assert_eq!(body["mode"], "drain");
        assert_eq!(body["timeout_secs"], 300);
        assert_eq!(body["force"], false);
        assert_eq!(body["operation_id"].as_str().unwrap().len(), 36);
        assert!(out.changed);
        assert_eq!(out.previous, Mode::Mesh);
        assert_eq!(out.mode, Mode::User);
        assert_eq!(out.free_confirmed, Some(true));
        assert_eq!(out.proof_secs, Some(20));
        let j = out.to_json();
        assert_eq!(j["gpu_free_confirmed"], true);
        assert_eq!(j["gpu"]["free_mb"], 15000);
        assert_eq!(j["lease"]["generation"], 4);
        assert!(f.said[0].contains("draining its GPU backends"), "{:?}", f.said);
    }

    #[test]
    fn user_immediate_and_unconfirmed_free() {
        let mut stuck_gc = user_gc(5000, 0);
        stuck_gc["noomesh_mb"] = json!(2000);
        let mut f = Fake { node: node(free_gc(), warm()), on_hold: node(stuck_gc, stopped()), ..Default::default() };
        let mut a = args("awolf", Want::User);
        a.immediate = true;
        let out = run(&mut f, &a, Want::User).unwrap();
        assert_eq!(f.bodies[0]["mode"], "immediate");
        assert!(f.said[0].contains("--immediate"), "{:?}", f.said);
        assert_eq!(out.free_confirmed, Some(false), "the hold is on, the free state is flagged");
        assert_eq!(out.mode, Mode::User);
        assert_eq!(f.clock, FREE_CONFIRM_SECS as i64);
        assert_eq!(out.to_json()["gpu_free_confirmed"], false);
    }

    #[test]
    fn refusals_have_kinds_and_remedies() {
        let plan = |n: Value, want: Want| match decide(&n, want) {
            Plan::Refuse(r) => r,
            other => panic!("not a refusal: {other:?}"),
        };
        let manual = node(json!({"state": "held", "reason": "voice", "lease": {"owner": "rbwolf", "operation_id": "op-1", "generation": 2}}), stopped());
        let r = plan(manual.clone(), Want::User);
        assert_eq!(r.kind, "gpu_held_by_other");
        assert!(r.hint.unwrap().starts_with("noo cluster gpu hold awolf --force"));
        let r = plan(manual, Want::Mesh);
        assert_eq!(r.kind, "gpu_held_by_other");
        assert!(r.hint.unwrap().starts_with("noo cluster gpu release awolf --operation op-1 --generation 2"));
        let reserved = node(json!({"state": "held", "lease": {"operation_id": "res-9", "workload": "rhaddon/worker"}}), stopped());
        let r = plan(reserved.clone(), Want::Mesh);
        assert!(r.hint.as_deref().unwrap().starts_with("noo cluster release res-9"), "{r:?}");
        assert_eq!(plan(reserved, Want::User).kind, "gpu_held_by_other");
        let draining = node(json!({"state": "draining", "lease": {"owner": "rbwolf"}}), stopped());
        assert_eq!(plan(draining.clone(), Want::Mesh).kind, "gpu_transition_in_progress");
        assert_eq!(plan(draining, Want::User).kind, "gpu_transition_in_progress");
        let yielded = node(json!({"state": "yielded", "foreign_mb": 9000}), stopped());
        assert_eq!(plan(yielded, Want::Mesh).kind, "gpu_yielded");
        let off = json!({"id": "awolf", "status": "offline", "gpu_contention": {"state": "free"}});
        assert_eq!(plan(off, Want::User).kind, "node_not_reporting");
        assert_eq!(plan(json!({"id": "awolf", "status": "online"}), Want::User).kind, "gpu_not_reported");
        let lost = node(json!({"state": "free", "method": "not-measured", "unmeasured": "driver-lost"}), stopped());
        let r = plan(lost, Want::User);
        assert_eq!(r.kind, "gpu_not_measurable");
        assert!(r.msg.contains("reboot"), "{}", r.msg);
        let none = node(json!({"state": "free", "method": "not-measured", "unmeasured": "no-nvidia"}), stopped());
        assert_eq!(plan(none, Want::User).kind, "gpu_not_measurable");
        let unleased = node(json!({"state": "held", "method": "nvidia-smi", "lease": {"purpose": "user"}}), stopped());
        assert_eq!(plan(unleased, Want::Mesh).kind, "gpu_hold_refused");
    }

    #[test]
    fn gateway_refusals_map_to_the_existing_kinds() {
        let r = gateway_refusal("awolf", "hold", 409, &json!({"error": "drain_timeout: still in flight after 2m0s (vllm: 1)"}).to_string());
        assert_eq!(r.kind, "gpu_drain_timeout");
        assert!(r.remote);
        assert!(r.hint.unwrap().starts_with("noo cluster gpu mode awolf user --timeout 600"));
        let r = gateway_refusal("awolf", "hold", 409, &json!({"error": "held_by_other: held by a (operation op-1, generation 2)"}).to_string());
        assert_eq!(r.kind, "gpu_held_by_other");
        let r = gateway_refusal("awolf", "release", 409, "transition_in_progress: x");
        assert_eq!(r.kind, "gpu_transition_in_progress");
        let r = gateway_refusal("awolf", "hold", 500, "boom");
        assert_eq!((r.kind, r.remote), ("remote_error", true));
        let mut f = Fake { node: node(free_gc(), warm()), hold_err: Some((409, "drain_timeout: busy".into())), ..Default::default() };
        let r = run(&mut f, &args("awolf", Want::User), Want::User).unwrap_err();
        assert_eq!(r.kind, "gpu_drain_timeout");
        let mut f = Fake { node: node(user_gc(15000, 0), stopped()), release_err: Some((409, "held_by_other: held by a".into())), ..Default::default() };
        let r = run(&mut f, &args("awolf", Want::Mesh), Want::Mesh).unwrap_err();
        assert_eq!(r.kind, "gpu_held_by_other");
    }

    #[test]
    fn show_reads_the_mode_without_writing() {
        let mut f = Fake { node: node(user_gc(15000, 0), stopped()), ..Default::default() };
        let out = show(&mut f, "awolf").unwrap();
        assert_eq!(out.mode, Mode::User);
        assert!(!out.changed);
        assert!(f.calls.is_empty());
        assert_eq!(out.to_json()["lease"]["operation_id"], "op-7");
        let mut f = Fake { node: node(free_gc(), warm()), ..Default::default() };
        assert_eq!(show(&mut f, "awolf").unwrap().mode, Mode::Mesh);
    }

    #[test]
    fn parses_the_arguments() {
        assert_eq!(parse_gpu_mode(&a(&["awolf"])),
            Ok(GpuModeArgs { node: "awolf".into(), mode: None, timeout: None, immediate: false, wait: None, no_wait: false }));
        assert_eq!(parse_gpu_mode(&a(&["awolf", "user", "--timeout", "300", "--immediate"])),
            Ok(GpuModeArgs { node: "awolf".into(), mode: Some(Want::User), timeout: Some(300), immediate: true, wait: None, no_wait: false }));
        assert_eq!(parse_gpu_mode(&a(&["--wait", "120", "awolf", "mesh"])),
            Ok(GpuModeArgs { node: "awolf".into(), mode: Some(Want::Mesh), timeout: None, immediate: false, wait: Some(120), no_wait: false }));
        assert!(parse_gpu_mode(&a(&["awolf", "mesh", "--no-wait"])).unwrap().no_wait);
        assert!(parse_gpu_mode(&a(&[])).is_err());
        assert!(parse_gpu_mode(&a(&["awolf", "vr"])).unwrap_err().to_string().contains("unknown mode"));
        assert!(parse_gpu_mode(&a(&["awolf", "voice"])).unwrap_err().to_string().contains("not available yet"));
        assert!(parse_gpu_mode(&a(&["awolf", "user", "mesh", "x"])).is_err());
        assert!(parse_gpu_mode(&a(&["awolf", "mesh", "--wait", "5", "--no-wait"])).is_err());
        assert!(parse_gpu_mode(&a(&["awolf", "mesh", "--immediate"])).is_err(), "immediate is for user");
        assert!(parse_gpu_mode(&a(&["awolf", "mesh", "--timeout", "5"])).is_err(), "timeout is the drain's");
        assert!(parse_gpu_mode(&a(&["awolf", "user", "--no-wait"])).is_err());
        assert!(parse_gpu_mode(&a(&["awolf", "user", "--wait", "5"])).is_err());
        assert!(parse_gpu_mode(&a(&["awolf", "--immediate"])).is_err(), "a flag with no mode changes nothing");
        assert!(parse_gpu_mode(&a(&["awolf", "user", "--timeout", "soon"])).is_err());
        assert!(parse_gpu_mode(&a(&["awolf", "user", "--bogus"])).is_err());
    }
}
