# Harness protocol

The contract between the gateway and a harness: what a harness is handed,
what it may call back, and what it must publish. `noo-gateway harness`
(`gateway-rust/src/harness_main.rs`) is the reference implementation. A
foreign loop (`claude-code`, `copilot`, `codex`) is a wrapper that
speaks this protocol; nothing else about the gateway is visible to it.

The names below are the code's names. A test in
`gateway-rust/src/coordinator/rail.rs` fails if an operation or subject
named here drifts from the code.

## 1. What a harness is

A harness is an agent loop placed on a node, next to that node's chat
backend, so a turn runs beside its model instead of on the controller. Two
independent axes describe a placement:

- **Which loop** is the *kind*: `noo`, `claude-code`, `copilot`, `codex`
  (declared once in `config/harness-kinds.json`; `NOO_HARNESS_KIND` on the
  placement).
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
| `NOO_HARNESS_KIND` | the loop kind (a kind from `config/harness-kinds.json`). Not in the shipped env file: when unset, the reference harness asks its node agent, `GET /harness/placement` on the model endpoint's agent (`{"kind", "env", "desired_state", "placed"}`), and runs `noo` when the agent answers 404 or `placed: false`. Any other answer (unreachable, 401/403, 5xx, a body that does not parse) is asked again a few times, then the harness exits non-zero with `harness: cannot learn this node's harness kind from its agent: <cause>; refusing to guess` — it never guesses `noo` under a placement it could not read. The node agent reports the kind it started the harness with as `host_services.harness.kind` while it runs. It runs its own loop for `noo` and the foreign-CLI driver (section 9) for any other kind |
| `NOO_HARNESS_TURN_TIMEOUT_SECS` | a foreign CLI's wall-clock limit per invocation (default 900) |
| `NOO_HARNESS_WORKDIR` | where the driver makes each task's workspace (default: the process temp dir, which the shipped unit makes private) |
| `NOO_HARNESS_KEEP_WORKDIR` | `1` keeps a task's workspace after it ends, for debugging |

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
| 400 | an unresolvable backend, a failed cloud run, an alert kind outside the allowed set, a `usage` report naming an undeclared harness kind |
| 401 | the token expired, or its account is now disabled, absent, or holds a lower role than the token: the account is re-read on every call, cached at most 10 s, so disabling a person or lowering their role stops a running turn within that bound rather than at the token's expiry. A role raised mid-turn takes effect at the next mint (checkpoint renewal or the next dispatch) |
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
| `usage` | report the tokens a foreign loop's model calls used (`prompt_tokens`, `completion_tokens`, `total_tokens`, `calls`, `model`, `kind`, `task_id` optional), as the wire translator counted them; recorded in `noo_token_usage` as the token's user on the token's node, with source `harness`, backend `harness:<kind>` and the `harness_kind` column; `kind` must be a kind in `config/harness-kinds.json`. With a `task_id` that is this token's task, the row carries the task id and the tokens are added to the task's `tokens_spent` before the reply (which then carries `tokens_spent`) |

**A task's loops**

| `op` | Purpose |
|---|---|
| `task_checkpoint` | record a loop boundary (`task_id`, `loops`, `note`, `exhausted`); replies `state` and a fresh `token` that replaces the old one |
| `task_done` | a foreign CLI's verdict on its task (`task_id`, `result`, `failed`): what `noo_task_done` is for a native loop. The task must be this token's (403 otherwise). As for `noo_task_done` from the user door, there is no tool-use evidence gate (the CLI's tools ran on the node, outside noomesh's record); the result is recorded as given and posted to the task's thread; replies `state` |
| `budget_check` | the token switch, asked BEFORE a loop starts and never during one (`task_id`): replies `proceed`, `reason`, `remaining_task`, `remaining_allowance`, `state` and, once after the owner answered a question, `clarification` (`question`, `answer`) for the next loop's prompt. On `proceed: false` the runner stops; the gateway has already parked the task (`budget_state` `exhausted` or `awaiting_clarification`) and posted the reason to its thread. The task must be this token's (403 otherwise) |
| `task_usage` | a native loop's tokens, run on a node (`task_id`, `prompt_tokens`, `completion_tokens`, `model`, `backend`): recorded in `noo_token_usage` with source `task`, the task id, the token's user and node and the backend that served it, and added to the task's `tokens_spent`; replies `tokens_spent`. A `cloud-*` or `harness:*` backend is refused (400): cloud models run on the controller, and a foreign loop reports with `usage` |
| `task_ask` | a loop's question to its owner (`task_id`, `question`): recorded and posted to the task's thread. The loop is not interrupted; at the next `budget_check` the task parks `awaiting_clarification` and waits for the owner's answer, which starts a new loop |

**A foreign CLI's way back in**

| `op` | Purpose |
|---|---|
| `door_key` | mint a user-door key for the token's person: a `noo_service_keys` row with scope `mcp`, bound to that user, consumer `harness:<node>:<conversation prefix>`, expiring with the turn (never later than the token, never longer than `NOO_HARNESS_TURN_TIMEOUT_SECS`). Replies `key` (shown once), `key_id` and `expires_at`. 403 when the person has no active account |
| `door_key_revoke` | revoke a key `door_key` minted (`key_id`), for the same person only; replies `revoked`. An unrevoked key stops working at `expires_at` and is deleted by the next mint |

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

### Wire translator

A foreign loop is a vendor CLI, and the CLI speaks its vendor's wire, not
the node backend's. The harness does not point the CLI at
`NOO_HARNESS_MODEL_URL`. For each CLI invocation (one task loop, or one turn) it starts a wire translator
(`gateway-rust/src/harness/translator.rs`) and gives the CLI that
translator's base URL, `http://127.0.0.1:<port>`, as the CLI's model base
URL. The port is ephemeral and the translator stops when the invocation ends.

| Route | The CLI sends | The translator sends to the endpoint |
|---|---|---|
| `POST /v1/chat/completions` | OpenAI chat (Copilot CLI) | the same body on an OpenAI-wire backend (vLLM, llama.cpp, the node agent), or Ollama's `/api/chat` with the reply converted back |
| `POST /v1/messages` | Anthropic Messages (Claude Code) | the request converted to OpenAI chat, with the reply converted back to a Messages response or a Messages event stream |
| `POST /v1/responses` | OpenAI Responses (Codex CLI) | the request converted to OpenAI chat, with the reply converted back to a Responses object or the Responses event stream (`response.created` ... `response.completed`) |
| `GET /v1/models` | | nothing. The answer is one entry, the pinned model |

Streaming and non-streaming both work on every route. The translator
replaces whatever model the CLI names with the pinned model. Any other path
gets a 404 with a JSON error body.

The Responses route is stateless. Codex CLI sends the whole conversation in
`input` on every request (its HTTP requests carry no
`previous_response_id`), so the translator keeps nothing between calls and
serves no `GET /v1/responses/{id}`; a request that names a
`previous_response_id` gets a 400. The conversion (in
`gateway-rust/src/coordinator/responses_wire.rs`, shared with the gateway's
own `/v1/responses`) hoists the instructions and every developer message
into one leading system message, merges consecutive user messages, turns
`function_call` and `custom_tool_call` items into chat tool calls and their
outputs into tool messages, and drops `reasoning` items. Function tools,
freeform `custom` tools (as a function with one string argument `input`)
and the tools inside a `namespace` (as `<namespace>__<name>`) go to the
backend; hosted tools such as `web_search` do not. On the way back each call
is returned under the name, namespace and item type the CLI declared.
Request fields with no chat equivalent (`store`, `include`, `reasoning`,
`prompt_cache_key`, ...) are dropped.

The translator counts every model call: the reply's usage, or, for a
stream, its final usage chunk or Ollama's closing object. A reply without
usage still counts as a call. When the invocation ends, the harness reports the
totals with the `usage` operation, so the gateway meters a foreign loop's
model calls the same way it meters its own.

The listener is plain HTTP on loopback with no auth. That is acceptable
because the translator is per-process and per-task, binds `127.0.0.1` on a
port the kernel picked, and dies with the task. Anything that can reach it
already runs on the node as a local user and can read the credentials the
harness itself uses. The translator forwards only to the one pinned
endpoint and holds no credential of its own. Its upstream calls use the
cluster CA and the node agent's bearer, the same as the reference loop's.

## 9. The foreign-CLI driver

For a kind other than `noo`, `noo-gateway harness` is still the runner:
the bus, the ack, the permit, `harness_result` and `task_checkpoint` are
exactly as above. What changes is the loop. Each task loop (and each turn)
is ONE invocation of the vendor's headless CLI (`cli` and `launch` in
`config/harness-kinds.json`), driven by `gateway-rust/src/harness/driver.rs`:

1. Start the wire translator on loopback, in front of the pinned endpoint.
2. Mint a user-door key (`door_key`).
3. Make the task's workspace under `NOO_HARNESS_WORKDIR`: a `home/`
   that becomes the CLI's `HOME` (its config and state directory too, via
   `launch.home_env`), and the MCP config file naming
   `{NOO_GATEWAY_URL}/mcp/user` with the door key as the bearer (mode 0600).
   `launch.mcp` says which file: `config-file` is a `{"mcpServers": ...}`
   JSON file beside `home/`, passed as `{mcp_config}`;
   `config-file:codex-toml` is Codex CLI's whole `config.toml` in its
   `CODEX_HOME` (`home/.codex/`). Codex takes its model URL from no
   variable, so that file names the translator as a provider
   (`base_url = <translator>/v1`, `wire_api = "responses"`) and the pinned
   model, adds the user door as a streamable-HTTP MCP server, sets
   `approval_policy = "never"` with `sandbox_mode = "danger-full-access"` (the harness's Landlock jail is the sandbox; Codex's own bubblewrap cannot run inside it),
   and switches Codex's reporting off
   ([../security/telemetry.md](../security/telemetry.md#agent-harnesses)).
4. Build the CLI's environment from nothing: `PATH`, `HOME`, `LANG`,
   `TMPDIR`, the translator's URL and the pinned model under the kind's
   variable names (none for Codex), a placeholder provider key,
   `NODE_EXTRA_CA_CERTS` (the cluster CA, also under `launch.ca_env`, which
   is `CODEX_CA_CERTIFICATE` for Codex), the model's context window under
   `launch.context_window_env` (`CLAUDE_CODE_MAX_CONTEXT_TOKENS` for Claude
   Code) when the node agent's `/harness/placement` answer carries
   `model_context`, then the kind's `lane`, then its
   `telemetry_off`, last. No
   `NATS_*` and no `NOO_*` variable reaches the CLI: not the bus pair, not
   the node-agent bearer, not the turn token.
5. Run `launch.command` with `{prompt}` and `{mcp_config}` filled in, in
   the workspace, stdin closed, output captured up to a cap, killed (its
   whole process group) at `NOO_HARNESS_TURN_TIMEOUT_SECS` or the key's
   expiry, whichever is sooner.
6. Read the verdict. A task prompt asks for a last line
   `NOO_RESULT: <summary>` when the objective is achieved or
   `NOO_FAILED: <reason>` when it cannot be; either one becomes `task_done`.
   `NOO_QUESTION: <question>` when it cannot go on without the owner
   becomes `task_ask`. None of them means more loops. Before each run the
   driver asks `budget_check`; a `proceed: false` ends the task's runner
   (the task is parked, not failed). A non-zero exit is a failed loop, its stderr
   tail the note; three in a row end the task, as for the native loop.
7. Save the prompt and the answer (`session_save`), report the translator's
   token counts (`usage`), `task_checkpoint` (exhausted when the loop reached the
   budget without a verdict), revoke the key, stop the translator, and
   remove the workspace when the task ends (unless
   `NOO_HARNESS_KEEP_WORKDIR=1`).

A turn sends one `content` event with the answer, then `harness_result`.
A kind whose `launch` still carries an `unverified:` value is refused at
start.

A kind may also declare `launch_slim`, with the same fields as `launch`.
Only claude-code has one. The driver runs it instead of `launch` while the
node's harness profile (`profile.claude_prompt` in the agent's
`/harness/placement` answer) says `slim`. It reads the choice once per run
and re-reads the placement every minute. `launch_slim.system_prompt_file`
names a file in the task's HOME. Before the run, the driver writes its slim
system prompt there (mode 0600) and passes the path as
`{system_prompt_file}` in `command`. It removes the file after the run. A
command that names `{system_prompt_file}` without declaring the file is
refused at start, and so is a file name that is not a plain name.

`model_context` in the agent's `/harness/placement` answer is the context
window the node's chat backend runs with. For Ollama it is what the agent
sets: `OLLAMA_CONTEXT_LENGTH`, the placement's own value or else the
profile's `ollama_context` default. For vLLM and llama.cpp the agent asks the
running backend (vLLM's `max_model_len` from `GET /v1/models`, llama-server's
per-slot `n_ctx` from `GET /props`, which is `--ctx-size` divided across its
parallel slots), bounded at 2 seconds. It is absent when the agent does not
know (another backend, nothing set, the backend not answering, an older
agent), and then the CLI keeps its own default. Without it Claude Code assumes a 200k window for a model it
does not know, so on a 32k node it never compacts before Ollama truncates
the prompt. The driver reads the window once per run, and the harness
re-reads the placement every minute.

`noo-gateway harness probe --kind <kind>` runs steps 1, 3, 4 and 5 once,
with no door key and no MCP wiring. That means no `{mcp_config}`
arguments and no `[mcp_servers]` table. The probe uses either the node's
model or a scripted mock, and changes nothing outside its temp workspace.
See [../getting-started/supported-agent-harnesses.md](../getting-started/supported-agent-harnesses.md#probe-a-kind-before-placing-it).
