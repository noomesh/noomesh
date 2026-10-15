# Harness protocol

The contract between the gateway and a harness: what a harness is handed,
what it may call back, and what it must publish. `noo-gateway harness`
(`gateway-rust/src/harness_main.rs`) is the reference implementation. A
foreign loop (`claude-code`, `copilot`, a future `codex`) is a wrapper that
speaks this protocol; nothing else about the gateway is visible to it.

The names below are the code's names. A test in
`gateway-rust/src/coordinator/rail.rs` fails if an operation or subject
named here drifts from the code.

## 1. What a harness is

A harness is an agent loop placed on a node, next to that node's chat
backend, so a turn runs beside its model instead of on the controller. Two
independent axes describe a placement:

- **Which loop** is the *kind*: `noo`, `claude-code`, `copilot`
  (`HARNESS_KINDS` in `gateway-rust/src/routes/cluster.rs`;
  `NOO_HARNESS_KIND` on the placement).
- **Which model** is the *endpoint*: the one chat backend the harness was
  placed beside (`NOO_HARNESS_MODEL_URL`, `NOO_HARNESS_MODEL`,
  `NOO_HARNESS_BACKEND`). A harness is pinned to it and never asks the
  gateway to choose a backend for its own model calls.

Our loop (kind `noo`) is the reference: it takes turns and tasks on the
bus, and does everything else (memory, retrieval, session, tools,
approvals) by calling back to the gateway over HTTPS. Which kinds run today
is in [../getting-started/supported-agent-harnesses.md](../getting-started/supported-agent-harnesses.md).

The gateway dispatches a turn to a harness only when the turn has a user
(heartbeat and research turns do not), the resolved model is served by a
node with a harness, and `NOO_HARNESS_DISPATCH` is not `0`, `false` or
`off` (the operator's brake). Otherwise the gateway runs the turn itself.

## 2. Identity

A harness presents two credentials, and they do different jobs.

**The node's bus principal.** The only credential on the bus.
`NATS_NODE_USER` and `NATS_NODE_PASSWORD` (or `NATS_NODE_PASSWORD_FILE`),
over TLS verified against `NOO_TLS_CA`. The principal's grant allows it to
subscribe `harness.run.<node>` and `harness.task.<node>`, publish
`harness.turn.<node>.>` and `harness.ready.<node>`, and use the inbox
prefix `_INBOX_node_<id>` (the id reduced to `[A-Za-z0-9_-]`). It can
publish into no other node's subjects. There is no shared fallback pair;
a missing pair is a refusal at start.

**The per-turn user token.** Every turn and task arrives carrying `token`,
a JWT the gateway minted for that one conversation
(`auth::mint_harness_jwt`):

| Claim | Value |
|---|---|
| `sub` | the user the turn runs as |
| `role` | that user's role |
| `harness` | `node:<id>`, the node it was handed to |
| `conv` | the conversation id, pinned |
| `exp` | `NOO_HARNESS_TURN_TIMEOUT_SECS` (default 900) plus 60 s |

The token is a user token, not a service credential. The auth middleware
confines a `harness` token to paths under `/api/harness/`
(`auth::harness_turn_for`): anywhere else, or with an empty `conv`, it is
403. The conversation and the user are taken from the token, never from a
request body, so a harness cannot name another conversation or person. The
token is signed with `NOO_JWT_SECRET`; with no secret the gateway does not
dispatch.

## 3. Environment a runner receives

The node agent sets all of this from the placement.

| Variable | Meaning |
|---|---|
| `NODE_ID` | this node's id; the subject it listens on |
| `NOO_GATEWAY_URL` | the controller, e.g. `https://gateway:8080` |
| `NOO_TLS_CA` | the cluster CA (HTTPS to the gateway, TLS to the bus) |
| `NATS_URL` | the bus |
| `NATS_NODE_USER`, `NATS_NODE_PASSWORD` | the node's bus principal; the password may arrive as `NATS_NODE_PASSWORD_FILE`, never both |
| `NOO_HARNESS_MODEL_URL`, `NOO_HARNESS_MODEL`, `NOO_HARNESS_BACKEND` | the model endpoint, its name, its backend type (default `openai`) |
| `NOO_HARNESS_MAX_TURNS` | concurrent turns and tasks (default 8) |
| `NOO_HARNESS_KIND` | the loop kind of the placement (`noo`, `claude-code`, `copilot`); the node agent reads it to choose the runner, the reference harness does not |

`NODE_ID`, `NOO_GATEWAY_URL`, `NATS_URL`, `NOO_HARNESS_MODEL_URL` and
`NOO_HARNESS_MODEL` are required; the reference harness refuses to start
without them.

## 4. Inbound: the bus

All subscriptions use the queue group `harness`. A node id or conversation
id in a subject has `.`, `*`, `>` and spaces replaced by `_`.

| Subject | Payload | Source |
|---|---|---|
| `harness.run.<node>` | a turn, `TurnRequest` | `coordinator/dispatch.rs` |
| `harness.task.<node>` | a task, `TaskRequest` | `tasks.rs` |
| `harness.ready.<node>` | published by the harness: `{"node": "<id>"}` | `tasks.rs` |

`TurnRequest` fields: `conversation_id`, `prompt`, `channel`,
`max_iterations`, `model` (optional), `user`, `enable_thinking` (default
false), `role_prompt` (optional), `stream` (default false: send only the
result), `token`.

`TaskRequest` fields: `task_id`, `objective`, `conversation_id`,
`thread_id`, `channel`, `user`, `model` (optional), `loops_done`,
`loop_budget`, `max_iterations`, `token`, `role_prompt` (optional).

**Ack.** Both arrive as NATS requests. A harness that takes the work
replies on the request's reply subject with `{"ack": true, "node": "<id>"}`.
The gateway waits 3 seconds. No ack, a reply that is not `ack: true`, or
no responder means the work was not taken, and the gateway runs it itself.

**At capacity.** A harness at its `NOO_HARNESS_MAX_TURNS` limit does not
ack. That is the whole refusal; there is no negative reply. An
unparseable payload is dropped without an ack.

**Ready.** At start, after subscribing, the harness publishes
`harness.ready.<node>`. The gateway answers by handing back that node's
checkpointed tasks on `harness.task.<node>`.

Order at start: connect to the bus, subscribe `harness.run.<node>` and
`harness.task.<node>`, then announce on `harness.ready.<node>`.

## 5. The rail: `POST /api/harness/call`

Everything a harness needs from the cluster goes through one route:

```
POST {NOO_GATEWAY_URL}/api/harness/call
Authorization: Bearer <the turn's token>
{"op": "<name>", ...}
```

An operation runs through the same functions the gateway's own loop calls,
so a remote turn reads, writes, audits and is rate-limited as a local one.
No operation carries a conversation or user; both come from the token. An
unknown `op` is refused.

**Replies.** Success is HTTP 200 and a JSON object with `"ok": true` plus
the fields below. Failure is a non-2xx status and, usually, a body
`{"error": "..."}`:

| Status | When |
|---|---|
| 400 | an unresolvable backend, a failed cloud run, an alert kind outside the allowed set |
| 403 | not a node-harness token (even an admin token is refused); `task_checkpoint` for a task that is not this turn's; the closed cloud gate on `cloud_run`, whose body is the cloud-gate body (`code: cloud_providers_disabled`) |
| 500 | a session write failed |

The reference client times a call out at 3700 s, because `execute_tool`
can wait on an approval.

**At connect.** The runtime calls `config` once, then `catalogs` once, and
selects skills and runbooks locally for every message after that; there is
no rail call per layer. A gateway that cannot ship `catalogs` leaves the
loop without those two layers; that is logged, not fatal.

### The operations

Wire names, as `HarnessOp::name()` returns them. Parameters are in the
request object beside `op`.

**Configuration**

| `op` | Purpose |
|---|---|
| `config` | `max_context_tokens`, `max_session_messages`, `preferred_skills` |
| `catalogs` | `skills` and `runbooks`, fetched once at connect |

**The model**

| `op` | Purpose |
|---|---|
| `model_preference` | the user's saved model preference |
| `detect_model` | pick a model from the prompt (`prompt`) |
| `resolve_backend` | resolve a backend (`model`, `exclude_urls`); a pinned harness uses its own endpoint instead |
| `cloud_run` | run a cloud completion (`prompt`, `channel`, `model`); refused with 403 when the cloud gate is closed |

**The session**

| `op` | Purpose |
|---|---|
| `session_load` | the conversation's messages (`channel`) |
| `session_save` | append a message (`role`, `content`, `metadata`) |
| `session_metadata` | update the conversation's metadata (`metadata`) |
| `turn_number` | this conversation's turn count |

**Context layers** (each returns `text`, `null` or empty when there is none)

| `op` | Purpose |
|---|---|
| `persona` | the persona prompt |
| `cluster_awareness` | what the cluster looks like |
| `rag` | knowledge-base context (`prompt`) |
| `memory` | memory context (`prompt`) |
| `cross_channel` | context from other channels (`prompt`, `channel`) |
| `video` | video context (`prompt`) |
| `companion` | companion context |
| `skills` | prompt skills for the message (`prompt`, `preferred`) |
| `runbook` | runbook context (`prompt`) |
| `temporal` | temporal context (`timeout_ms`, capped at 30000) |
| `running_summary` | the conversation's running summary |
| `recall` | conversation recall (`query`, `top_k`, capped at 50) |

**Tools**

| `op` | Purpose |
|---|---|
| `tool_schemas` | `native` and `external` tool schemas for this user |
| `execute_tool` | run one tool call (`call`: `id`, `name`, `arguments`) as the person, through the approval gate; replies `result` |

**A turn's side effects** (each replies `{"ok": true}`)

| `op` | Purpose |
|---|---|
| `record_tool_call` | audit a tool call (`tool_name`, `arguments`, `success`, `output`, `error`, `elapsed_ms`) |
| `retrieval_feedback` | retrieval feedback (`tool_name`, `success`) |
| `skill_usage` | skills that were used (`names`) |
| `pre_hooks` | fire pre-inference hooks (`prompt`) |
| `post_hooks` | fire post-response hooks (`result`, the `CoordinatorResult`) |
| `shard` | tag the conversation's shard |
| `temporal_extract` | temporal extraction (`user_message`, `assistant_response`) |
| `maybe_summary` | regenerate the running summary if due (`backend`, `turn`) |
| `operator_alert` | raise an operator alert (`kind`, `target`, `cooldown_secs`, `message`); only `inference.backend_failover` is allowed, and the gateway writes the channel text itself |

**A task's loops**

| `op` | Purpose |
|---|---|
| `task_checkpoint` | record a loop boundary (`task_id`, `loops`, `note`, `exhausted`); replies `state` and a fresh `token` that replaces the old one |

## 6. Outbound: events

A harness publishes the loop's events on
`harness.turn.<node>.<conversation>`, where `<node>` is its own `NODE_ID`
(the bus grant is written against it). The gateway subscribes before it
hands the turn over, so no event is lost. It also still listens on the
legacy subject `harness.turn.<conversation>` for harnesses older than
noo-cli 0.5.41; nothing should publish it.

Each message is a JSON object with a `type`. A string payload is
`{"type": "<event>", "text": "..."}`; an object payload has its fields
beside `type`. The loop emits `metadata`, `content`, `thinking`,
`tool_call`, `tool_result`, `done` and `error`; the gateway forwards every
event it does not recognise unchanged, onto whatever is waiting on the
turn (the dashboard socket, a channel).

| Event | What the gateway does |
|---|---|
| `harness_result` | **last event of a successful turn**: `{"result": <CoordinatorResult>, "node": "<id>"}`. Kept, not forwarded; ends the relay. |
| `error` | forwarded; ends the relay. The turn fails. |
| `done` | forwarded; the gateway then waits at most 10 more seconds for `harness_result`. |
| anything else | forwarded |

Rules:

- A non-streaming turn (`stream: false`) sends only `harness_result` (or
  `error`).
- Send `harness_result` after the loop returns, immediately. A turn that
  produces neither `harness_result` nor `error` within
  `NOO_HARNESS_TURN_TIMEOUT_SECS` (default 900) is a lost turn.
- **A lost turn is an error, never re-run.** Once a harness acked, its
  tools may already have executed, so the gateway does not run the turn
  again itself.
- Tasks have no event stream: a task reports through `task_checkpoint`
  only, and holds one concurrency permit for its whole life.

## 7. Approvals and gated tools on a remote turn

`execute_tool` runs on the gateway, under the person's identity, in a
different task from the one that dispatched the turn. The gateway
registers where the turn came from (the dashboard socket or the channel
that asked) for as long as it is in flight, so an approval card for a gated
call goes back to that origin exactly as if the loop ran in process. A
remote turn has no dashboard socket of its own on the rail.

Denied high-risk calls and completed identical calls are recorded per turn
on the gateway, so duplicate-call suppression works across a remote turn's
loops and the dispatcher can hand failures to the channel's banner. A
harness does nothing for this beyond calling `execute_tool` and treating
its `result` as final: it must not retry a denied call on its own, and it
must not execute gated tools locally.

## 8. What a foreign runner must do

1. Read the environment in section 3. Refuse to start if a required
   variable is missing.
2. Connect to the bus as the node principal only (`NATS_NODE_USER` and
   `NATS_NODE_PASSWORD`, TLS against `NOO_TLS_CA`, inbox prefix
   `_INBOX_node_<id>`). Present no other credential.
3. Subscribe `harness.run.<node>` and `harness.task.<node>` in queue group
   `harness`, then publish `{"node": "<id>"}` on `harness.ready.<node>`.
4. For each request: parse it; if at capacity, do nothing; otherwise reply
   `{"ack": true, "node": "<id>"}` on the reply subject within 3 seconds.
5. Use the request's `token` as the bearer on `POST /api/harness/call`
   and on nothing else. Take no conversation or user from anywhere but the
   request. For a task, replace the token with the one `task_checkpoint`
   returns.
6. Call `config` and `catalogs` once at the start of a turn.
7. Load and save the session, build context from the layer operations,
   and execute every tool through `execute_tool`. Record what happened
   with the side-effect operations.
8. Send model calls to the endpoint in `NOO_HARNESS_MODEL_URL` only.
9. For a streaming turn publish events on
   `harness.turn.<node>.<conversation>`; end every turn with exactly one
   `harness_result` or one `error`.
10. For a task, run up to `loop_budget - loops_done` loops, calling
    `task_checkpoint` after each, and stop when the returned `state` is not
    `running` or `checkpointed` or the budget is reached.
11. Never re-run a turn, and never publish on another node's subjects.
