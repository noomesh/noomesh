// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The task tools on the user MCP door (`/mcp/user`): `noo_task_delegate`,
//! `noo_task_status`, `noo_task_wait`, `noo_task_done` — for a caller with no
//! native loop around it (a foreign CLI harness, a person's own client on a
//! laptop) to open, watch, wait on and finish mesh tasks (i83 E1d) — and the
//! token-budget tools (i83 G): `noo_task_ask` (a question to the owner, as
//! the in-loop tool), `noo_task_resubmit` (raise the budget, resume) and
//! `noo_task_answer` (answer the question, start a new loop).
//!
//! **Why these are not manifest tools.** Every other door tool is a
//! `mcp-tools.json` entry the door turns into an HTTP self-call under the
//! caller's JWT. These four are natives inside a task's loop
//! (`tools.rs`), where the task is implicit — found through the loop's
//! conversation. On the door there is no loop: the task is NAMED, so the
//! check is an owner check on the id, made here against the key's bound
//! account. Doing it in process (like the `mcp_bridge` catalog) rather than
//! through `/api/tasks` keeps two rules the HTTP routes do not have:
//!
//! - an Admin on this door is still scoped to their OWN tasks (the routes
//!   let an Operator+ read everyone's; the door acts AS the account, and
//!   the operator door is where operator reach lives);
//! - a wait is bounded by [`WAIT_MAX_SECS`], so it returns `state: running`
//!   instead of holding the door's request open.
//!
//! Tier: every account the door admits (User and above), the same widening
//! as the other user-door tools; nothing here reaches past the caller's own
//! tasks. A task that is not the caller's reads as "task not found" whether
//! it exists or not — the same answer `GET /api/tasks/{id}` gives, so the
//! door is no oracle for other people's task ids.
//!
//! Audit: the door's `mcp_tool_call` record covers these exactly as it does
//! every other door tool (`mcp_external::handle`); there is no second path.

use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::state::AppState;
use crate::tasks::Task;
use crate::tools::task_tree::brief;

pub const DELEGATE: &str = "noo_task_delegate";
pub const STATUS: &str = "noo_task_status";
pub const WAIT: &str = "noo_task_wait";
pub const DONE: &str = "noo_task_done";
pub const ASK: &str = "noo_task_ask";
pub const RESUBMIT: &str = "noo_task_resubmit";
pub const ANSWER: &str = "noo_task_answer";

/// All of them, in the order `tools/list` advertises them.
pub const TOOLS: &[&str] = &[DELEGATE, DONE, STATUS, ASK, RESUBMIT, ANSWER, WAIT];

/// The ones a task's own loop also has, under the same name (`tools.rs`).
/// Resubmit and answer are the OWNER's moves, never the loop's.
pub const LOOP_TOOLS: &[&str] = &[DELEGATE, DONE, STATUS, WAIT, ASK];

/// The longest one `noo_task_wait` call holds the door: the gateway's bound
/// for holding any request (`ops::MAX_WAIT_SECS`, short of every proxy
/// timeout in front of it). Past it the wait returns the task as it stands
/// (`state: running`, `timed_out: true`) and the client calls again. The
/// in-loop wait allows 600s because nothing sits between it and the runner.
pub const WAIT_MAX_SECS: u64 = crate::ops::MAX_WAIT_SECS;
/// The wait when the caller names none.
pub const WAIT_DEFAULT_SECS: u64 = WAIT_MAX_SECS;
/// How often a wait re-reads the task.
const WAIT_POLL: std::time::Duration = std::time::Duration::from_secs(2);

/// What `noo_task_status` lists when it is given no id.
const STATUS_LIST_LIMIT: i64 = 20;

const NOT_FOUND: &str = "task not found";

pub fn is_tool(name: &str) -> bool {
    TOOLS.contains(&name)
}

fn live(state: &str) -> bool {
    matches!(state, "open" | "running" | "checkpointed")
}

/// The `tools/list` entries, in the door's `{name, description, inputSchema}` shape.
pub fn tool_list() -> Vec<Value> {
    let roles = crate::agent_roles::AgentRole::known_names().join(", ");
    vec![
        json!({
            "name": DELEGATE,
            "description": format!(
                "Open a mesh task for yourself and start it on the node holding its model. With `parent_task_id` \
                 (one of your live tasks) it is a sub-task that posts to the parent's thread, at most {} deep and \
                 {} per parent; without, a top-level task on a fresh thread. Returns task_id, thread_id, node, \
                 dispatched and why.",
                crate::tasks::MAX_DEPTH, crate::tasks::MAX_CHILDREN
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "objective": {"type": "string", "description": "What the task must achieve."},
                    "parent_task_id": {"type": "string", "description": "One of your live tasks to delegate under. Omit for a top-level task."},
                    "role": {"type": "string", "description": format!("Role its loops run under: {roles}.")},
                    "model": {"type": "string", "description": "Model to run it on. Omit for the default."},
                    "loop_budget": {"type": "integer", "minimum": 1, "maximum": 500, "description": "Loops it may take. Omit for the default of the node it lands on (else the cluster's)."},
                    "token_budget": {"type": "integer", "minimum": 1, "description": "Tokens its loops may spend (prompt + completion). Omit for no cap of its own."}
                },
                "required": ["objective"]
            }
        }),
        json!({
            "name": DONE,
            "description": "Finish one of your tasks: record its result (or, with failed=true, why it failed) and post \
                            it to the task's thread.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Your task to finish."},
                    "result": {"type": "string", "description": "The result, or the reason it failed."},
                    "failed": {"type": "boolean", "default": false, "description": "True when the objective could not be achieved."}
                },
                "required": ["task_id", "result"]
            }
        }),
        json!({
            "name": STATUS,
            "description": "One of your tasks with its sub-tasks (state, loops, last note, result, error), or with no \
                            task_id your most recent top-level tasks.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Your task. Omit to list your recent tasks."}
                }
            }
        }),
        json!({
            "name": ASK,
            "description": "Ask the owner of one of your tasks a question it cannot go on without. The question is posted \
                            to the task's thread; the running loop finishes, then the task waits for the answer \
                            (budget_state awaiting_clarification).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Your task."},
                    "question": {"type": "string", "description": "One clear question."}
                },
                "required": ["task_id", "question"]
            }
        }),
        json!({
            "name": RESUBMIT,
            "description": "Give one of your tasks more tokens. A task stopped because its token budget ran out \
                            (budget_state exhausted) resumes from its checkpoint; on a running task this only \
                            changes its cap.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Your task."},
                    "token_budget": {"type": "integer", "minimum": 1, "description": "The new cap, in tokens. Omit to resume under the same cap (after an allowance was raised or turned over)."}
                },
                "required": ["task_id"]
            }
        }),
        json!({
            "name": ANSWER,
            "description": "Answer the question one of your tasks asked (budget_state awaiting_clarification): a new \
                            loop starts with the question and your answer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Your task."},
                    "text": {"type": "string", "description": "Your answer."}
                },
                "required": ["task_id", "text"]
            }
        }),
        json!({
            "name": WAIT,
            "description": format!(
                "Wait for one of your tasks: returns when it settles (done, failed, stopped), when one of its \
                 sub-tasks settles, or after `seconds` (at most {WAIT_MAX_SECS}) with the task as it stands — \
                 state running means call again."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Your task."},
                    "seconds": {"type": "integer", "minimum": 1, "maximum": WAIT_MAX_SECS, "default": WAIT_DEFAULT_SECS}
                },
                "required": ["task_id"]
            }
        }),
    ]
}

/// What the door's task tools read and write. The database in service; a
/// fake in the tests, so the owner rules are exercised without Postgres.
trait TaskStore {
    async fn get(&self, id: &str) -> anyhow::Result<Option<Task>>;
    async fn children(&self, id: &str) -> anyhow::Result<Vec<Task>>;
    async fn list(&self, owner: &str, limit: i64) -> anyhow::Result<Vec<Task>>;
    async fn finish(&self, id: &str, ok: bool, text: &str, require_tool_use: bool) -> anyhow::Result<bool>;
}

struct Db<'a>(&'a sqlx::PgPool);

impl TaskStore for Db<'_> {
    async fn get(&self, id: &str) -> anyhow::Result<Option<Task>> {
        crate::tasks::get(self.0, id).await
    }
    async fn children(&self, id: &str) -> anyhow::Result<Vec<Task>> {
        crate::tasks::children(self.0, id).await
    }
    async fn list(&self, owner: &str, limit: i64) -> anyhow::Result<Vec<Task>> {
        crate::tasks::list(self.0, Some(owner), None, limit).await
    }
    async fn finish(&self, id: &str, ok: bool, text: &str, require_tool_use: bool) -> anyhow::Result<bool> {
        crate::tasks::finish(self.0, id, ok, text, require_tool_use).await
    }
}

fn arg<'a>(args: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
}

/// The task, if it is the caller's. Anything else — another account's, an
/// ownerless one, an unknown or malformed id — is the same "not found".
/// The caller's role does not widen this: the door acts as the account.
async fn owned<S: TaskStore>(store: &S, user: &str, id: &str) -> Result<Task, String> {
    match store.get(id).await {
        Ok(Some(t)) if t.owner.as_deref() == Some(user) => Ok(t),
        Ok(_) => Err(NOT_FOUND.into()),
        Err(e) => Err(format!("task lookup failed: {e}")),
    }
}

/// The parent a door delegation names: one of the caller's LIVE tasks, or
/// none for a top-level task. A settled parent cannot take a sub-task —
/// nothing would ever read its result.
async fn parent_for<S: TaskStore>(store: &S, user: &str, args: &Map<String, Value>) -> Result<Option<Task>, String> {
    let Some(id) = arg(args, "parent_task_id") else { return Ok(None) };
    let parent = owned(store, user, id).await?;
    if !live(&parent.state) {
        return Err(format!("task {} is already {}; delegate under a live task, or omit parent_task_id", parent.id, parent.state));
    }
    Ok(Some(parent))
}

async fn status<S: TaskStore>(store: &S, user: &str, args: &Map<String, Value>) -> Result<Value, String> {
    let Some(id) = arg(args, "task_id") else {
        let tasks = store.list(user, STATUS_LIST_LIMIT).await.map_err(|e| format!("task list failed: {e}"))?;
        return Ok(json!({"tasks": tasks.iter().map(brief).collect::<Vec<_>>()}));
    };
    let task = owned(store, user, id).await?;
    let kids = store.children(&task.id).await.map_err(|e| format!("children lookup failed: {e}"))?;
    Ok(snapshot(&task, &kids))
}

fn snapshot(task: &Task, kids: &[Task]) -> Value {
    let mut out = brief(task);
    out["thread_id"] = json!(task.thread_id);
    out["parent_id"] = json!(task.parent_id);
    out["children"] = json!(kids.iter().map(brief).collect::<Vec<_>>());
    out["all_settled"] = json!(kids.is_empty() || crate::tasks::aggregate(kids).is_some());
    out
}

/// Wait on the caller's task until it settles, one of its sub-tasks
/// settles, or `seconds` (clamped to [`WAIT_MAX_SECS`]) pass. Never longer:
/// on the deadline the task comes back as it stands, with `timed_out`.
async fn wait<S: TaskStore>(store: &S, user: &str, args: &Map<String, Value>, poll: std::time::Duration) -> Result<Value, String> {
    let Some(id) = arg(args, "task_id") else { return Err("task_id is required".into()) };
    let task = owned(store, user, id).await?;
    let secs = args.get("seconds").and_then(Value::as_u64).unwrap_or(WAIT_DEFAULT_SECS).clamp(1, WAIT_MAX_SECS);
    let started = tokio::time::Instant::now();
    let until = started + std::time::Duration::from_secs(secs);
    let mut seen_live = None::<usize>;
    let mut task = task;
    loop {
        let kids = store.children(&task.id).await.map_err(|e| format!("children lookup failed: {e}"))?;
        let live_kids = kids.iter().filter(|k| live(&k.state)).count();
        let child_settled = seen_live.is_some_and(|n| live_kids < n);
        let now = tokio::time::Instant::now();
        let timed_out = now >= until;
        if !live(&task.state) || child_settled || timed_out {
            let mut out = snapshot(&task, &kids);
            out["waited_secs"] = json!(now.duration_since(started).as_secs());
            out["timed_out"] = json!(timed_out && live(&task.state) && !child_settled);
            return Ok(out);
        }
        seen_live = Some(live_kids);
        tokio::time::sleep(poll.min(until.saturating_duration_since(now))).await;
        task = match store.get(&task.id).await {
            Ok(Some(t)) => t,
            Ok(None) => return Err(NOT_FOUND.into()),
            Err(e) => return Err(format!("task lookup failed: {e}")),
        };
    }
}

/// Finish the caller's task through the same `tasks::finish` the loop's
/// `noo_task_done` uses, minus the evidence gate (`require_tool_use: false`). Returns the task as it
/// was and whether it succeeded, for the result post.
async fn finish<S: TaskStore>(store: &S, user: &str, args: &Map<String, Value>) -> Result<(Task, bool, String), String> {
    let Some(id) = arg(args, "task_id") else { return Err("task_id is required".into()) };
    let task = owned(store, user, id).await?;
    let failed = args.get("failed").and_then(Value::as_bool).unwrap_or(false);
    let text = arg(args, "result").or_else(|| arg(args, "reason")).unwrap_or_default().to_string();
    // No evidence gate from the door: the caller is an external agent whose
    // tool use happens outside the task's conversation, so "called no tool"
    // would be read off a record that never holds its calls.
    match store.finish(&task.id, !failed, &text, /* require_tool_use */ false).await {
        Ok(true) => Ok((task, !failed, text)),
        Ok(false) => Err(format!("task {} is already {}", task.id, task.state)),
        Err(e) => Err(format!("could not finish task: {e}")),
    }
}

/// The caller's task the arguments name, or why not.
async fn named<S: TaskStore>(store: &S, user: &str, args: &Map<String, Value>) -> Result<Task, String> {
    let Some(id) = arg(args, "task_id") else { return Err("task_id is required".into()) };
    owned(store, user, id).await
}

/// Run one of the task tools for the door's caller (`user` is the key's bound account).
pub async fn call(state: &Arc<AppState>, user: &str, name: &str, args: &Map<String, Value>) -> Result<Value, String> {
    let store = Db(&state.db);
    match name {
        DELEGATE => {
            let parent = parent_for(&store, user, args).await?;
            let argv = Value::Object(args.clone());
            crate::tools::task_tree::delegate(state, Some(user), parent.as_ref(), &argv).await
        }
        STATUS => status(&store, user, args).await,
        WAIT => wait(&store, user, args, WAIT_POLL).await,
        DONE => {
            let (task, ok, text) = finish(&store, user, args).await?;
            crate::tools::post_task_result(state, &task, user, ok, &text).await;
            Ok(json!({"task_id": task.id, "state": if ok { "done" } else { "failed" }}))
        }
        ASK => {
            let task = named(&store, user, args).await?;
            let q = arg(args, "question").unwrap_or_default();
            crate::task_budget::ask(state, &task, q).await.map_err(|e| e.to_string())?;
            Ok(json!({"task_id": task.id, "asked": true}))
        }
        RESUBMIT => {
            let task = named(&store, user, args).await?;
            let budget = args.get("token_budget").and_then(Value::as_i64);
            let (after, started) = crate::task_budget::resubmit(state, &task, budget).await.map_err(|e| e.to_string())?;
            let mut out = brief(&after);
            out["resumed"] = json!(started.is_some());
            if let Some(s) = started {
                out["node"] = json!(s.node);
                out["dispatched"] = json!(s.dispatched);
                out["queued"] = json!(s.queued);
            }
            Ok(out)
        }
        ANSWER => {
            let task = named(&store, user, args).await?;
            let text = arg(args, "text").or_else(|| arg(args, "answer")).unwrap_or_default();
            let (after, started) = crate::task_budget::answer(state, &task, text).await.map_err(|e| e.to_string())?;
            let mut out = brief(&after);
            out["node"] = json!(started.node);
            out["dispatched"] = json!(started.dispatched);
            out["queued"] = json!(started.queued);
            Ok(out)
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn task(id: &str, owner: Option<&str>, state: &str, parent: Option<&str>) -> Task {
        Task {
            id: id.into(),
            objective: format!("objective of {id}"),
            owner: owner.map(str::to_string),
            node: None,
            state: state.into(),
            conversation_id: format!("conv-{id}"),
            thread_id: "thr_1".into(),
            channel: "task".into(),
            model: None,
            loops: 0,
            loop_budget: 20,
            last_checkpoint: None,
            last_note: None,
            result: None,
            error: None,
            created_at: String::new(),
            updated_at: String::new(),
            parent_id: parent.map(str::to_string),
            role: None,
            budget_default: false,
            stale: false,
            token_budget: None,
            tokens_spent: 0,
            budget_state: None,
            remaining: None,
            created_via: None,
        }
    }

    /// In-memory tasks; `finish` behaves like `tasks::finish_row` (only a
    /// live task finishes) and records every call.
    #[derive(Default)]
    struct Fake {
        tasks: Mutex<Vec<Task>>,
        finished: Mutex<Vec<(String, bool, String)>>,
        /// Child id settled on the Nth `children` read (for the wait tests).
        settle_on_read: Mutex<Option<(String, usize)>>,
        reads: Mutex<usize>,
    }

    impl Fake {
        fn with(tasks: Vec<Task>) -> Self {
            Fake { tasks: Mutex::new(tasks), ..Default::default() }
        }
    }

    impl TaskStore for Fake {
        async fn get(&self, id: &str) -> anyhow::Result<Option<Task>> {
            Ok(self.tasks.lock().unwrap().iter().find(|t| t.id == id).cloned())
        }
        async fn children(&self, id: &str) -> anyhow::Result<Vec<Task>> {
            let mut reads = self.reads.lock().unwrap();
            *reads += 1;
            if let Some((child, n)) = self.settle_on_read.lock().unwrap().clone() {
                if *reads >= n {
                    for t in self.tasks.lock().unwrap().iter_mut().filter(|t| t.id == child) {
                        t.state = "done".into();
                    }
                }
            }
            Ok(self.tasks.lock().unwrap().iter().filter(|t| t.parent_id.as_deref() == Some(id)).cloned().collect())
        }
        async fn list(&self, owner: &str, _limit: i64) -> anyhow::Result<Vec<Task>> {
            Ok(self.tasks.lock().unwrap().iter().filter(|t| t.owner.as_deref() == Some(owner) && t.parent_id.is_none()).cloned().collect())
        }
        async fn finish(&self, id: &str, ok: bool, text: &str, require_tool_use: bool) -> anyhow::Result<bool> {
            let mut tasks = self.tasks.lock().unwrap();
            let Some(t) = tasks.iter_mut().find(|t| t.id == id) else { return Ok(false) };
            if !live(&t.state) {
                return Ok(false);
            }
            // The fake's tasks have recorded no tool calls, so the gate,
            // when asked for, refuses a success claim as `tasks::finish` does.
            if ok && require_tool_use {
                anyhow::bail!("refused: this task has not called a single tool");
            }
            t.state = if ok { "done" } else { "failed" }.into();
            t.result = Some(text.into());
            self.finished.lock().unwrap().push((id.into(), ok, text.into()));
            Ok(true)
        }
    }

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    fn fixture() -> Fake {
        Fake::with(vec![
            task("mine", Some("alice"), "running", None),
            task("mine-kid", Some("alice"), "running", Some("mine")),
            task("theirs", Some("bob"), "running", None),
            task("ownerless", None, "running", None),
            task("mine-done", Some("alice"), "done", None),
        ])
    }

    /// Every task tool is advertised in the door's tool shape, each with a schema.
    #[test]
    fn the_task_tools_are_listed_with_schemas() {
        let list = tool_list();
        let names: Vec<&str> = list.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, TOOLS, "listed in TOOLS order");
        for t in &list {
            assert!(!t["description"].as_str().unwrap().is_empty());
            assert_eq!(t["inputSchema"]["type"], "object", "{}", t["name"]);
        }
        let req = |n: &str| list.iter().find(|t| t["name"] == n).unwrap()["inputSchema"]["required"].clone();
        assert_eq!(req(DELEGATE), json!(["objective"]));
        assert_eq!(req(DONE), json!(["task_id", "result"]));
        assert_eq!(req(WAIT), json!(["task_id"]));
        assert!(req(STATUS).is_null(), "status takes no required argument");
        assert_eq!(req(ASK), json!(["task_id", "question"]));
        assert_eq!(req(RESUBMIT), json!(["task_id"]));
        assert_eq!(req(ANSWER), json!(["task_id", "text"]));
        assert!(TOOLS.iter().all(|n| is_tool(n)) && !is_tool("noo_rag_query"));
    }

    /// The same names the loop uses, so a harness prompt reads the same on
    /// either side — and no manifest tool shadows them on the door.
    #[test]
    fn the_names_are_the_native_ones_and_not_in_the_manifest() {
        for n in TOOLS {
            assert!(crate::mcp_external::tool(n).is_none(), "{n} must not also be a manifest tool");
        }
        let src = include_str!("tools.rs");
        for n in LOOP_TOOLS {
            assert!(src.contains(&format!("\"{n}\" => Some(")), "{n} is a native tool in tools.rs");
        }
        // The owner's moves are not the loop's: a task cannot raise its own
        // budget or answer its own question.
        for n in [RESUBMIT, ANSWER] {
            assert!(!src.contains(&format!("\"{n}\"")), "{n} must not be a loop tool");
        }
    }

    /// The door wires them for every caller it admits (no tier filter: a
    /// User-tier key lists and calls them like an Admin's), dispatches them
    /// to this module as the key's ACCOUNT, and audits the call through the
    /// door's one `mcp_tool_call` record BEFORE running it.
    #[test]
    fn the_door_lists_audits_then_dispatches_them_as_the_account() {
        let src = include_str!("mcp_external.rs");
        let handle = &src[src.find("async fn handle(").expect("handle")..src.find("#[cfg(test)]").expect("tests")];
        let list = &handle[handle.find("\"tools/list\" =>").expect("tools/list arm")..handle.find("\"tools/call\" =>").expect("tools/call arm")];
        assert!(list.contains("crate::mcp_user_tasks::tool_list()"), "tools/list must advertise the task tools");
        assert!(!list.contains("user_role"), "the listing is not tier-filtered");
        let call = &handle[handle.find("\"tools/call\" =>").unwrap()..];
        let audit = call.find("\"mcp_tool_call\"").expect("the door's audit row");
        let dispatch = call.find("crate::mcp_user_tasks::call(&state, &caller.user, name, args)").expect("dispatched as the account");
        assert!(audit < dispatch, "the call is audited before it runs");
        assert_eq!(call.matches("audit_event(").count(), 1, "one audit path, not a second one for task tools");
    }

    /// Another account's task, an ownerless one and an unknown id all read
    /// "task not found" — on every tool that takes an id.
    #[tokio::test]
    async fn other_peoples_tasks_are_not_found_on_every_tool() {
        let store = fixture();
        for id in ["theirs", "ownerless", "no-such-task"] {
            let a = args(json!({"task_id": id, "parent_task_id": id, "result": "x", "seconds": 1}));
            assert_eq!(status(&store, "alice", &a).await.unwrap_err(), NOT_FOUND, "status {id}");
            assert_eq!(wait(&store, "alice", &a, std::time::Duration::from_millis(1)).await.unwrap_err(), NOT_FOUND, "wait {id}");
            assert_eq!(finish(&store, "alice", &a).await.unwrap_err(), NOT_FOUND, "done {id}");
            assert_eq!(parent_for(&store, "alice", &a).await.unwrap_err(), NOT_FOUND, "delegate under {id}");
            // ask, resubmit and answer resolve their task through `named`.
            assert_eq!(named(&store, "alice", &a).await.unwrap_err(), NOT_FOUND, "ask/resubmit/answer {id}");
        }
        assert!(store.finished.lock().unwrap().is_empty(), "nothing was finished");
        assert_eq!(store.tasks.lock().unwrap().iter().find(|t| t.id == "theirs").unwrap().state, "running");
    }

    /// Done on one's own task records it through `finish`, exactly once,
    /// with the result text; a second done says it is already done.
    #[tokio::test]
    async fn done_on_own_task_records_completion() {
        let store = fixture();
        let (t, ok, text) = finish(&store, "alice", &args(json!({"task_id": "mine", "result": "42 documents"}))).await.unwrap();
        assert_eq!((t.id.as_str(), ok, text.as_str()), ("mine", true, "42 documents"));
        assert_eq!(*store.finished.lock().unwrap(), vec![("mine".to_string(), true, "42 documents".to_string())]);
        let again = finish(&store, "alice", &args(json!({"task_id": "mine", "result": "again"}))).await.unwrap_err();
        assert!(again.contains("already done"), "{again}");

        let (_, ok, _) = finish(&store, "alice", &args(json!({"task_id": "mine-kid", "result": "no route", "failed": true}))).await.unwrap();
        assert!(!ok, "failed=true records a failure");
        assert!(finish(&store, "alice", &args(json!({"result": "x"}))).await.unwrap_err().contains("task_id"));
    }

    /// A door caller's tool use is outside the task's conversation, so done
    /// from the door skips the evidence gate: a task with zero recorded tool
    /// calls finishes on the FIRST call, its result unprefixed.
    #[tokio::test]
    async fn door_done_does_not_require_prior_tool_calls() {
        let store = fixture();
        let (_, ok, text) = finish(&store, "alice", &args(json!({"task_id": "mine", "result": "answer"}))).await.expect("first call succeeds");
        assert!(ok);
        assert_eq!(text, "answer");
        let recorded = store.finished.lock().unwrap().clone();
        assert_eq!(recorded, vec![("mine".to_string(), true, "answer".to_string())]);
        assert!(!recorded[0].2.starts_with(crate::tasks::NO_TOOLS_MARK), "unprefixed");
        assert_eq!(store.tasks.lock().unwrap().iter().find(|t| t.id == "mine").unwrap().result.as_deref(), Some("answer"));
        // The loop's path still asks for the gate; the door's never does.
        assert!(include_str!("tools.rs").contains("/* require_tool_use */ true"));
        assert!(include_str!("mcp_user_tasks.rs").contains("/* require_tool_use */ false"));
    }

    /// Delegating under a parent needs it to be the caller's AND live; with
    /// no parent it is a top-level task.
    #[tokio::test]
    async fn delegate_parent_rules() {
        let store = fixture();
        assert!(parent_for(&store, "alice", &args(json!({"objective": "x"}))).await.unwrap().is_none());
        assert_eq!(parent_for(&store, "alice", &args(json!({"parent_task_id": "mine"}))).await.unwrap().unwrap().id, "mine");
        let e = parent_for(&store, "alice", &args(json!({"parent_task_id": "mine-done"}))).await.unwrap_err();
        assert!(e.contains("already done"), "{e}");
    }

    /// Status of one's own task carries its children; with no id it lists
    /// only the caller's top-level tasks.
    #[tokio::test]
    async fn status_is_own_tasks_only() {
        let store = fixture();
        let one = status(&store, "alice", &args(json!({"task_id": "mine"}))).await.unwrap();
        assert_eq!(one["task_id"], "mine");
        assert_eq!(one["children"][0]["task_id"], "mine-kid");
        assert_eq!(one["all_settled"], false);
        let all = status(&store, "alice", &args(json!({}))).await.unwrap();
        let ids: Vec<&str> = all["tasks"].as_array().unwrap().iter().map(|t| t["task_id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["mine", "mine-done"]);
    }

    /// A wait on a task that does not move returns at the deadline with the
    /// task still running — it never holds the door past the bound.
    #[tokio::test(start_paused = true)]
    async fn wait_returns_running_at_the_deadline() {
        let store = Fake::with(vec![task("mine", Some("alice"), "running", None)]);
        let t0 = tokio::time::Instant::now();
        let out = wait(&store, "alice", &args(json!({"task_id": "mine", "seconds": 5})), WAIT_POLL).await.unwrap();
        assert_eq!(out["state"], "running");
        assert_eq!(out["timed_out"], true);
        let took = t0.elapsed();
        assert!(took >= std::time::Duration::from_secs(5) && took < std::time::Duration::from_secs(6), "{took:?}");

        // An over-long ask is clamped to WAIT_MAX_SECS.
        let t0 = tokio::time::Instant::now();
        let out = wait(&store, "alice", &args(json!({"task_id": "mine", "seconds": 3600})), WAIT_POLL).await.unwrap();
        assert_eq!(out["timed_out"], true);
        assert!(t0.elapsed() <= std::time::Duration::from_secs(WAIT_MAX_SECS + 1), "{:?}", t0.elapsed());
    }

    /// A settled task returns at once; a sub-task settling ends the wait early.
    #[tokio::test(start_paused = true)]
    async fn wait_returns_early_when_something_settles() {
        let store = fixture();
        let t0 = tokio::time::Instant::now();
        let out = wait(&store, "alice", &args(json!({"task_id": "mine-done"})), WAIT_POLL).await.unwrap();
        assert_eq!((out["state"].as_str(), out["timed_out"].as_bool()), (Some("done"), Some(false)));
        assert_eq!(t0.elapsed(), std::time::Duration::ZERO);

        *store.settle_on_read.lock().unwrap() = Some(("mine-kid".into(), 3));
        let t0 = tokio::time::Instant::now();
        let out = wait(&store, "alice", &args(json!({"task_id": "mine", "seconds": 20})), WAIT_POLL).await.unwrap();
        assert_eq!(out["state"], "running");
        assert_eq!(out["children"][0]["state"], "done");
        assert_eq!(out["all_settled"], true);
        assert_eq!(out["timed_out"], false);
        assert!(t0.elapsed() < std::time::Duration::from_secs(10), "{:?}", t0.elapsed());
    }
}
