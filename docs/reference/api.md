# Gateway API Reference

The Rust gateway serves one HTTP surface on `:8080` (HTTPS when TLS is
configured), three WebSocket endpoints, and two MCP doors. Every route
below is registered in `gateway-rust/src/routes/*.rs` (the file is named
per section), plus a few top-level modules merged into the router in
`routes/mod.rs` (`mcp_external.rs`, `mcp_local.rs`, `addon_proxy.rs`); the
list is the router, not a summary of it.

```bash
# The gateway cert is signed by the cluster CA and names localhost/127.0.0.1,
# so verify against it rather than reaching for -k.
curl -s --cacert "${NOO_PKI_DIR:-$HOME/.config/mesh/pki}/ca.crt" https://localhost:8080/health | jq .status
```

The `noo` CLI is the supported client for all of this — every `noo` verb
is one of these calls. Use the API directly when you are writing your own
client or an agent.

## Authentication

Authentication is always on and fails closed: if `NOO_JWT_SECRET` is unset
the gateway refuses JWTs rather than accepting the well-known default. The
`require_any_auth` middleware (`auth.rs`) accepts, in order:

1. **A user JWT** (`Authorization: Bearer <token>`) from `POST /auth/token`.
   Role is derived from scopes: `admin` → Admin, `write` → Operator,
   otherwise User. Operators may call anything. Users may `GET` only an
   allow-list of the surfaces a person needs (conversations, memory, RAG and
   graph reads, their jobs, agent mail, usage, the dashboard's cluster/scheduler
   overview, the runbooks, `/ws/*`, and the add-on read routes whose manifest says `min_role: user`); a route not on the list
   is closed to a User until it is added on purpose, as for kiosk tokens.
   An add-on route that declares no `min_role` is Operator+ for every method (see
   [development/addons.md](../development/addons.md#who-may-call-a-route)).
   Installation-wide reads are Operator+: `/metrics`, `/api/metrics/*`,
   `/api/logs/*`, `/api/config*`, `/api/settings*` and `/api/v1/settings` (except
   `user-dirs` and `preference`), `/api/security/*` (audit, violations, PKI, posture,
   users, service keys; except the caller's own key), a node's
   `desired-config` and the other fleet reads under `/api/cluster/`, snapshots and
   the knowledge-base admin lists. The handlers behind the sensitive ones refuse a
   User themselves as well (`403 operator role required`), so a mis-edited
   allow-list cannot reopen them. `GET /api/coordinator/context` answers a User
   without backend URLs or peer ids. Users also
   use the chat and query surface (`/api/inference*`, `/api/conversations`,
   `/api/voice/`, `/upload`, `POST /api/v1/rag/query`, `/api/memory/search`,
   `POST /api/v1/graph/entities/resolve`, `/tools/select`), file a
   user-management proposal, mint or revoke their own MCP key, switch their
   own walk saving (`PUT /api/v1/walks/settings`), open Grafana as
   themselves, use the [async-operations API](#asynchronous-operations-routesopsrs)
   (each start is checked against the operation's own route), and — with the
   `ingest` scope — `POST /api/v1/docs/ingest`, and with the `graph` scope —
   the six graph query POSTs (`/api/v1/graph/classify-intent`, `/explain-path`,
   `/navigate`, `/search-clusters`, `/semantic-search`, `/traverse`; exact paths,
   nothing else under `/graph/`).
2. **A peer token** — a JWT with `scopes: ["peer"]` and `sub: "peer:<agent_id>"`,
   minted by `POST /api/agents/peer/register`. Confined to
   `/api/agents/peer*` and `/ws/agent`, and it acts as that ONE agent id.
   A user JWT is not a substitute: `/ws/agent` refuses one at the handshake
   whatever its role.
3. **The cluster HMAC token** (node-agents, the operator CLI credential):
   `node_id:timestamp:signature` signed with `NOO_CLUSTER_SECRET`. Some
   operations — approval decisions without a user, node-rail calls — are
   accepted from this credential. Posture writes are **not**: they take an
   operator client certificate plus an Admin token bound to it
   (`POST /api/security/operator-token`), and nothing else.
4. **A service key**, on `/v1/*` and
   `/api/external/*` only, with an optional per-minute quota
   (`429` + `Retry-After` when exceeded).

Public, no credential: `/auth/*`, `/api/auth/*`, `/assets/*`,
`/.well-known/*`, `/`, `/dashboard`, `/kiosk`, `/kiosk.html`,
`/favicon.ico`, `/docs`, and the enrollment endpoints a node
uses before it has credentials: `/bootstrap`, `/bootstrap/prep`, `/apply`,
`/deenroll`, `/fetch`, `/ca.crt`, `/bootstrap/cli/*`, `GET
/bootstrap/bundle/*`, `/api/cluster/bootstrap` and
`/api/cluster/enroll-tailnet` (the last two are gated by a
bootstrap token in the body or a tailnet
proof). `POST /api/kiosk/token/tailnet` is public for the same reason. Also
public on exact match: `/static/openapi.public.json`, a curated subset of
the API surface (the ~31 endpoints reachable without a credential).
`POST /mcp/user` and `POST /mcp/operator` skip the JWT middleware because
they authenticate a service key themselves ([MCP doors](#mcp-doors)).

**`/metrics` is not public.** It answers an Operator or Admin login, or the
Prometheus service certificate (`noo security pki issue-service prometheus`)
while mTLS enforcement is on (the default; `NOO_MTLS_GATEWAY=false` turns it off). The `/api/grafana-ds/*` routes answer only
Grafana's own service leaf.

`/health` is **credential-optional**, not flatly public: an anonymous
caller gets a reduced liveness body (status code only, in effect), while a
caller presenting any valid credential gets the full body shown below
(version, engine, peer count, dependency map). This exists so the
container healthcheck, compose healthcheck, and host watchdog — none of
which hold a credential — can still probe liveness, without handing that
same inventory to every anonymous caller on a shared tailnet.

`/static/*` is **not** a public prefix — only the exact path
`/static/openapi.public.json` is public, and it is a curated subset, not
the full spec. The full OpenAPI document for every route below is served
at `GET /api/docs/openapi`, which **requires auth**. Before 2026-09-19,
`/static/` was a public prefix, which made `/static/openapi.json` (the
full spec) readable by anything that could reach the gateway; that hole is
closed. See the security model
for more on this posture.

### `POST /auth/token`

Form (`application/x-www-form-urlencoded`) or JSON body with `username`
and `password`. Users are looked up in the database; before any exist, the
`NOO_ADMIN_USER` / `NOO_ADMIN_PASSWORD` bootstrap pair is accepted.

```bash
curl -s --cacert "${NOO_PKI_DIR:-$HOME/.config/mesh/pki}/ca.crt" -X POST https://localhost:8080/auth/token -d 'username=admin&password=…'
```

```json
{"access_token": "eyJ…", "token_type": "bearer", "expires_in": 900, "refresh_ttl_days": 30}
```

A refresh token is set as a cookie; `POST /auth/refresh` (alias
`/api/auth/refresh`) rotates it, `POST /auth/logout` revokes it (a bearer-only
logout, as the CLI makes, counts too) and ends the access token it was using,
`GET /auth/me` returns the caller's identity and scopes (`401` for a disabled
or deleted account, or a token issued before the account's session floor).

**Ending sessions.** `disable`, `set-role`, `set-scopes`, `set-password`,
`service-key revoke-and-disable` and an approved `disable`/`scopes` proposal
end the account's sessions immediately: every refresh token is revoked, open
`/ws/*` sockets close (4401), the service-key cache is dropped, and a per-account
"not before" time (Redis key `noo:auth:notbefore_ms:<account>`, unix milliseconds, plus the
durable Postgres row in `noo_session_floors.floor_ms`, both kept for one access-token lifetime;
the gateway loads the rows at boot) makes `require_any_auth` — and so the WebSocket handshake
— refuse any access token issued before it, so a reconnect with the old JWT
fails. A person's access token carries `iat_ms` (mint time in ms) beside `iat`;
a token without it counts from the start of its `iat` second. The floor is read from Redis, then the gateway's memory, then Postgres
(the highest wins), so a Redis outage or a restart does not forget one; if
neither store can be read the gateway applies the floors it holds in memory
(never fewer), logs a warning, and does not refuse every request.
`noo security admin-password reset` raises the same row from the host. Keys not
bound to the account are not touched by `disable`. Passwords set through
`POST /api/security/users` and `PUT …/{username}/password` must be at least
12 characters, not on the common list and not contain the username (`400`);
existing passwords are not re-checked. Lifetimes:
`NOO_TOKEN_EXPIRE_MINUTES` (15), `NOO_REFRESH_TOKEN_DAYS` (30). Failed
logins are audited and lock the account after repeated failures.

### Agent identity exchange

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/identity/token` | RFC 8693 token exchange: a provisioning service key (the bearer, the *actor*) trades a `subject_token` naming a mesh account for a short-lived user JWT for that account, carrying an `act` claim that names the key. The result is an ordinary user token; it is refused `403` on anything an `act` credential may not do (for example starting `graph.entity_cleanup`) |
| GET | `/.well-known/oauth-authorization-server`, `/.well-known/jwks.json` | exchange metadata and the signing keys (public) |
| POST | `/api/security/operator-certs/register`, `/revoke`; `/api/security/operator-token` | operator client certificates: register a leaf's thumbprint, revoke it, and mint an Admin token bound to a registered leaf (5 min). Posture writes need such a bound token |

## Health and metrics

### `GET /health`

Always HTTP 200; consumers key on the body. Credential-optional: an
anonymous caller gets a smaller body (liveness only); a caller presenting
any valid credential gets the full body below.

```json
{
  "status": "healthy",
  "engine": "rust",
  "version": "…",
  "peers": 2,
  "dependencies": {"postgresql": {"healthy": true}, "nats": {"healthy": true}, "redis": {"healthy": true, "optional": false}},
  "addons": {"trellion": "enabled", "evolve": "disabled", "trellion_intel": "disabled"}
}
```

`status` is `healthy` or `degraded`. Postgres and NATS gate it; Redis is
counted but does not flip it (a cache bounce must not fail the compose
healthcheck).

### `GET /metrics`

Prometheus text format — request counts and latencies, scheduler and
autonomy gauges, per-consumer usage. Operator/Admin login or the Prometheus
service certificate (not public). Add-ons push their counters and gauges
through `POST /api/metrics/increment` and `POST /api/metrics/gauge` (an
add-on service key with the `metrics` scope; at most 256 series per source,
`429` past it). See
[operating/observability.md](../operating/monitoring.md).

## Inference

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/inference` | run one turn through the coordinator (non-streaming) |
| POST | `/api/inference/stream` | the same, as Server-Sent Events proxied token-by-token from the backend (`data: {…}` lines in OpenAI streaming format, ending `data: [DONE]`) |
| POST | `/v1/chat/completions` | OpenAI-compatible chat, routed by **model class** with failover (below); what external clients and `pipeline/llm.py` use |
| POST | `/v1/responses` | OpenAI Responses API, for harnesses that speak only it (Codex CLI since February 2026); same auth, class resolution, failover and accounting as `/v1/chat/completions`. Streaming supported; stateless (no `GET /v1/responses/{id}`) |
| GET | `/v1/models`, `/v1/models/{model_id}` | the **catalogue**: every class and alias a consumer may send as `model`, `owned_by: "noomesh"`, with `noo: {class, candidates, healthy}`; `/v1/models/{id}` is `404 model_not_found` for an id that is no class, alias or served model. Still the dashboard's readiness probe: `503` until the first `chat-default` candidate answers its own model list |
| GET | `/api/tags`, `/api/version` | Ollama-compatible discovery so Ollama clients can point at the gateway |
| POST | `/api/tasks/inference` | submit inference as a scheduler job |
| POST | `/api/external/chat/completions`, `/api/external/inference`, `/api/external/embeddings`, `/api/external/rerank`, `/api/external/classify` | the service-key surface for external consumers; `chat/completions` (and `inference` with `kind: chat`) is the same class-routed path as `/v1/chat/completions` and honours `model` the same way. On `embeddings` (and `inference` with `kind: embedding`), `model` names an **embedding space** (`knowledge` when absent or `default`; a space's model name also selects it); an unknown one is 400 naming the spaces, never another model's vectors. `capabilities.embedding.spaces` lists them. On `rerank`, `model` is a preference: rerankers serving it go first, every other reranker after, then the LLM reranker; the answer's `noo` block says `served_by`, `model`, `fallback` and `requested_model` |
| GET | `/api/external/models`, `/api/external/capabilities`, `/api/external/usage` | the catalogue (same handler as `/v1/models`), what a consumer may call (`chat.models` and `classify.models` list the same ids), and its metered usage |
| GET, PUT, DELETE | `/api/cluster/model-classes`, `/api/cluster/model-classes/{class}` | operator: the live class table with every candidate's placement and health; declare / forget a class (`noo cluster class`) |
| PUT, DELETE | `/api/cluster/model-aliases/{alias}` | operator: point one alias (a purpose such as `knowledge`) at a class or served model `{class}`, tried first with the mesh behind it; a target nothing serves is accepted with a `note`; an alias may not hide a class or model of the same name (409). DELETE puts a purpose back on `chat-default` (`noo cluster prefer`) |
| GET, PUT, DELETE | `/api/cluster/embedding-spaces`, `/api/cluster/embedding-spaces/{space}` | operator: each embedding space (one model per purpose), its pool of role=embed placements and which advertise `embed`, plus placements on a model no space uses; declare a space `{model, dims?}` (changing an existing space's model is a 409: that is a re-embed); forget one (not `knowledge`) (`noo cluster embedding-space`) |
| POST, DELETE | `/api/cluster/embedding-spaces/{space}/migration` | operator: POST `{model}` starts re-embedding a space into another model (the gateway probes the model across its pool: 200 `filling`; 202 `pending` when no node serves it yet, and the gateway starts it once one does; 409 if one is running, the model belongs to a space, or its vector width differs from the space's); DELETE cancels while `pending` or `filling` (409 once `cutover`). `DELETE /api/cluster/embedding-spaces/{space}` is 409 while the space has any migration. The space listing and `capabilities.embeddings.spaces` carry `migration`: null or `{next_model, next_dims, state, progress, started_at, reported_at}` (`noo cluster embedding-space migrate`) |
| POST | `/api/cluster/embedding-spaces/{space}/migration/complete` | operator: begin the cutover; 409 unless the migration is `filling` and trellion's report (about this next model, under 10 minutes old) shows every table done == total |
| PUT | `/api/external/embedding-spaces/{space}/migration` | consumer key (scope `embeddings`): trellion's progress report `{next_model, tables: {<table>: {done, total, unsourced?}}, cutover_done}`; 409 with no migration, a `pending` one (not started: no node serves the model) or another next model; in `cutover`, `cutover_done: true` swaps the space to its next model in one UPDATE. Embeds with `model: "<space>@next"` on `/api/external/embeddings` use the next model (409 without a migration or while `pending`) |
| POST | `/api/external/embeddings/jobs` | consumer key (scope `embeddings`): a bulk embedding batch as a job. `{input: [..], space?, model?}` (`space` wins; both mean what `model` means on `/api/external/embeddings`, so `<space>@next` works) answers `202 {job_id, path, model}`. `path: pull`: a node that serves the model claims the batch from the `WORK_EMBED` work queue when it has a free embed slot (one slot per node stays free for query-time embeds); `path: push`: no node is pulling, so the gateway embeds it itself, two batches at a time. At most 64 texts per job and the encoded result must fit 600 KiB (`413`, the message names the cap); `429` + `Retry-After` when the model's queue holds over 5000 batches; `503` when no node serves the model. A pull job nobody claims within 2 minutes, or whose worker goes quiet, is run by the gateway once, then failed. Opt-in: the synchronous route never queues. Vectors are kept 15 minutes |
| GET | `/api/external/embeddings/jobs/{job_id}` | consumer key (scope `embeddings`): the caller's own embedding job (`404` for anyone else's); `?vectors=1` on a completed job adds `vectors` (one float32 row per input, in order). `410` once the 15 minutes are up: resubmit. The same job is readable at `GET /api/jobs/{job_id}?vectors=1` by a caller that reaches the scheduler routes |

### Model classes, failover and what the answer says

The `model` a consumer sends is a **class**, an **alias** or a concrete
served model name; it is never a node. A class is an ordered list of
`(node, backend, model)` candidates the operator declared (`noo cluster
class set`), or — with nothing declared — one derived class per served
model. Undeclared, `chat-default` (aliases `default`, `auto`, and an
absent `model`) is **dynamic**: every live chat node in the mesh, whatever
it serves, ranked per request (healthy, not stalled in the last 5 min, not
thermally hot, GPU not shared, vLLM/GPU before CPU, larger model, fewest
in flight, load; quarantined and thermal-`critical` nodes only when
nothing else is left). A declared `chat-default` puts its candidates first.

A `model` is a **preference**, not a selection: the class it names is
tried first, and behind it every other live chat node in that same
ranking, so a request is answered (perhaps slower, perhaps by a smaller
model) while any chat node is up. A model nothing serves right now — its
node is off doing something else — is answered by `chat-default` instead
of a `404`. `X-Noo-Served-Model` says what answered. Only a strict node
pin (below) never falls back.

To prefer one node, send `"node": "<id>"` in the body or an
`X-Noo-Node: <id>` header (also on `/api/inference` and the
`noo_inference` tool). That node is tried first, then the class's other
nodes, then the rest of the pool, and an answer from anywhere else says
`fallback: true` (`/api/inference` also returns `requested_node` and
`node_unavailable`). A name that is no node of this mesh is a `422`
(`node_not_found`) either way: a typo does not become "any node".

To keep a request on that node ALONE — locality, privacy, a liveness
check — add `"node_strict": true` or `X-Noo-Node-Strict: 1` (`0`,
`false`, `no`, `off` turn it off; any other value turns it on). A strict
request never reaches another node: `422` (`node_serves_no_chat`) when
the node serves no chat, `409` (`node_cannot_serve`) when it serves chat
but not the `model` named, and a `504`/`502` when it cannot answer.

The gateway tries
candidates in order (non-degraded before degraded, healthy before not,
declared position, load): a candidate that cannot be connected to within
5 s, that sends no response headers within 30 s on a streaming request,
or that answers a `502`/`503`/`504` marking the backend itself as down,
is skipped for the next one (at most three attempts, 300 s overall), and
the operator is alerted (`inference.backend_failover`, 15 min cooldown).
The 30 s window only decides when to move on: the last candidate a
request can still try gets the rest of the 300 s to start answering. A
class's `degraded: true` candidates come after its others and before the
rest of the mesh. A streaming answer is never retried once a byte has
reached the client.

Every chat answer says what served it:

| Where | What |
|---|---|
| headers | `X-Noo-Served-Class`, `X-Noo-Served-Model` |
| non-streaming body | `noo: {"class": "chat-default", "served_model": "gemma4:12b", "fallback": true}` beside the OpenAI fields |
| streaming | the first `data:` frame is an ordinary `chat.completion.chunk` with `"choices": []` and the `noo` object (the shape of vLLM's usage frame); the chunks follow unchanged. `/v1/responses` streams send no extra event — the headers carry it |

`fallback: true` means the answering candidate was not the class's first
choice. Nothing on this surface names a node, an address or a URL — the
headers are informational and are never accepted as credentials or
routing.

**Errors** on `/v1/*` and `/api/external/*` are general and carry a
reference: `{"error": {"message": "the inference backend did not answer",
"type": "backend_unavailable", "ref": "ref-3f9c2b1e0a"}}`. The detail
(which node, which address, the upstream body) is on the gateway log line
with that `ref` and, for `/api/external/*`, in the audit row
(`noo_external_requests.trace_id` / `error`) — **operator-side only**:
`GET /api/external/usage` returns the consumer its rows' `status_code` and
`ref`, never the `error` column. Types: `model_not_found`
(404 — no class, alias or served model by that name), `backend_unavailable`
(503 — nothing routable; 502 — every candidate failed), `backend_error`
(the backend answered with a non-retryable status), `bad_request`
(the message names the field).

### Reasoning models: thinking, budgets and structured output

A reasoning model (gemma4 on Ollama is the fleet's default) spends tokens
thinking before it answers, and on every backend those tokens come out of
the same budget as the answer: `max_tokens` is the **whole** generation,
reasoning included. A short probe with thinking on (`max_tokens: 64`)
returns `finish_reason: "length"` with an empty `content` and the
reasoning in `reasoning`/`reasoning_content`; that is the budget, not a
model fault. For a bounded structured answer:

- **Turn thinking off** with `"reasoning": {"effort": "none"}` (or
  `"reasoning_effort": "none"`, or Ollama's own `"think": false`). `none`
  and `minimal` both mean off on the native Ollama path; `low`, `medium`
  and `high` keep it on. `chat_template_kwargs.enable_thinking: false` is
  the vLLM/llama.cpp spelling and reaches Ollama's translator too (0.6.11);
  prefer the `reasoning` form, it is the portable one.
- **Budget with thinking on**: allow for the reasoning (gemma4 spends
  60–100 tokens on a yes/no) plus the answer; read `usage` and the
  `finish_reason`. The gateway refuses the one combination that can only
  come back empty: `response_format` set, thinking not turned off, and
  `max_tokens` under 256 → `400` with error `type`
  `budget_too_small_for_thinking` and both remedies in the message (turn
  reasoning off, or raise `max_tokens`). A request without
  `response_format`, without `max_tokens`, or with reasoning off in any of
  the spellings above is not touched.
- **`response_format`** (`json_object`, `json_schema`) is honoured as
  Ollama's `format`, but grammar-constrained decoding on a large-vocabulary
  model such as gemma4 runs at seconds per token on today's nodes. For a
  bounded answer ask for JSON in the prompt with thinking off and validate
  client-side; use `response_format` only where the per-token cost is
  acceptable.
- **A key the backend does not take is dropped**, not forwarded: the node
  agent keeps the portable OpenAI fields plus the vendor extras of the
  backend it picked (`think`/`reasoning`/`format`/`options` for Ollama,
  `guided_*`/`chat_template_kwargs` for vLLM, `n_predict`/`grammar` for
  llama.cpp). The answer names what was dropped in `X-Noo-Dropped-Keys`
  (sorted, comma-separated; absent when nothing was). A request that seems
  to ignore a control is one whose spelling was dropped: check that header.
- **Read `X-Noo-Served-Model`**: a fallback answer comes from a different
  (often smaller) model; pin with `node` + `node_strict: true` to refuse a
  fallback outright.

### Pointing an OpenAI SDK at the gateway

Use `base_url=https://<host>:8080/api/external`. The SDK appends
`chat/completions`, `embeddings` and `models`, and all three are served there.

**`/v1` is a chat-only back-compat alias**, kept for clients that predate the
external surface. It serves `chat/completions` and `models` and nothing else —
in particular there is no `/v1/embeddings`, so an SDK pointed at `/v1` fails on
`.embeddings.create()`. Point it at `/api/external` instead.

### Reasoning models return their thinking in a separate field

A reasoning-capable model (gemma4 among them) may spend its whole output budget
on reasoning and return `finish_reason: "length"` with **`content` empty and
`reasoning` populated**. A client that reads only `content` sees a silent empty
string rather than an error, so treat an empty `content` with a non-empty
`reasoning` as "budget exhausted before the answer", not as an answer.

Give reasoning models room: a 16-token budget can go entirely to reasoning, and
2048 has been observed still returning empty completions on structured output.
8192 is a working figure for large structured responses.

`POST /api/inference` body:

| Field | Type | Meaning |
|---|---|---|
| `prompt` | string | required |
| `conversation_id` | string | continue a session |
| `channel` | string | `api`, `dashboard`, `telegram`, … |
| `max_iterations` | int | cap on agentic rounds |
| `model` | string | override; `claude-*` / `gpt-*` / `gemini-*` go to a cloud provider when enabled |
| `stream` | bool | if true the response is a hint to use `/api/inference/stream` |
| `user_id` | string | ignored when a JWT identifies the caller — the token's subject wins |
| `node` | string | pin to one node id (bypasses model routing; what `noo inference run --node` uses) |
| `context` | bool | default `true`. `false` is a raw model call: no coordinator, no memory/document context, no conversation row — `prompt` is the only message, sent through the same resolver and usage accounting as `/v1/chat/completions` (a one-line prompt costs tens of prompt tokens instead of thousands). Honours `model`, `max_tokens`, `temperature`; the response has the same shape with `conversation_id: null`. A user-door JWT opens it; no `chat` consumer scope needed |
| `max_tokens`, `temperature` | number | sampling controls, honoured when `context` is `false` |

### Codex CLI on a mesh model (`POST /v1/responses`)

Codex CLI removed `wire_api = "chat"`; its providers speak only the Responses
API, so the gateway serves it. Point Codex at the controller:

```toml
[model_providers.noomesh]
name = "noomesh"
base_url = "https://<controller>:8080/v1"
env_key = "NOO_CHAT_KEY"
wire_api = "responses"
[profiles.mesh]
model_provider = "noomesh"
model = "google/gemma-4-12B-it-qat-w4a16-ct"
```

`NOO_CHAT_KEY` is an operator-issued service key with the `chat` scope
(`noo security service-key issue <you>-chat --scopes chat --user <you>`). The
`:8080` URL presents the cluster CA, so the machine running Codex needs it
trusted (`noo security trust-ca`).

A vLLM backend reached directly is proxied to its own `/v1/responses`; every
other backend (Ollama, llama.cpp, anything behind a node-agent) is served by
translating to chat completions: `input` + `instructions` become `messages`,
`max_output_tokens` becomes `max_tokens`, `function` tools carry over, and the
completion comes back as a Responses object (`output_text` / `function_call`
items, `usage.input_tokens`/`output_tokens`). `stream: true` emits the
Responses event sequence (`response.created` through `response.completed`).
Hosted tools (`web_search`, …) are dropped.


## WebSocket

| Path | Purpose |
|---|---|
| `/ws/coordinator` | chat streaming |
| `/ws/collab` | multi-agent collaboration relay (tokens, tool calls, peer injects, start/done per role) |
| `/ws/agent` | agent-to-agent peer transport — a peer token ONLY (`sub: peer:<agent_id>`), and the `agent_hello.agent_id` must equal its subject; a user JWT is refused at any role |

Connect with `?token=<jwt>`; the handshake fails closed when the JWT secret
is unconfigured. On `/ws/coordinator` the client sends
`{"prompt", "conversation_id", "user_id", "enable_thinking", "model"}` and
receives flat JSON events, each with a `type`:

```json
{"type": "metadata", "conversation_id": "…", "model": "…", "backend": "…"}
{"type": "thinking", "text": "…"}
{"type": "content", "text": "token"}
{"type": "content_clear"}
{"type": "tool_call", "name": "web_search", "arguments": {}}
{"type": "tool_result", "name": "web_search", "success": true, "output": "…"}
{"type": "error", "text": "…"}
{"type": "done", "iterations": 3, "tool_calls": 2, "elapsed_seconds": 15.2}
{"type": "keepalive"}
```

## Cluster and nodes (`routes/cluster.rs`, `routes/bootstrap.rs`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/cluster/status` | nodes, backends, scheduler and knowledge-base summary |
| GET | `/api/cluster/nodes` | the node registry (from the `mesh_nodes` KV bucket merged with the database) |
| POST | `/api/cluster/nodes/register`, `/api/cluster/nodes/{id}/register` | node-agent registration (hostname, ip, tier, capabilities) |
| POST | `/api/cluster/nodes/{id}/heartbeat` | node-agent heartbeat: `load`, `cpu_load`, `cpu_cores`, `ram_gb`, `mem_used_gb`, `gpu_model`, `vram_gb`, `vram_used_gb`, `running_backends`, `ip_address`; `404` tells the agent to re-register |
| DELETE | `/api/cluster/nodes/{id}/forget` | remove a node |
| GET | `/api/cluster/nodes/{node_id}/desired-config` | what the node-agent reconciles against |
| PUT | `/api/cluster/nodes/{node_id}/config` | set node config (`usage_profile`: `shared` \| `dedicated` \| null for the default) |
| PUT, DELETE | `/api/cluster/nodes/{node_id}/placements/{backend}` | declare / remove a placement, keyed (node, backend, role): PUT takes `role` in the body (absent = `chat`), `force`, `target` (`cpu` \| `gpu`; `cpu` refused for vLLM, `gpu` refused on a node with no GPU) and `model_size_bytes` (a fit-check size hint, not stored); a llama.cpp placement stores a derived container `memory_limit_bytes` and the response carries `memory_limit` `{bytes, why}`; a does-not-fit memory verdict is a 409 unless forced; DELETE takes `?role=<role>` (`all` for every role; refused when several roles exist and none is named) (`noo cluster place` / `unplace`) |
| POST | `/api/cluster/nodes/{node_id}/fit` | read-only memory-fit verdict for the node's placements, optionally with one more (`{"with": {backend, model, role, env, target, model_size_bytes}}`), one budget per pool (`budgets`: gpu and cpu) (`noo cluster fit`) |
| POST | `/api/cluster/nodes/{node_id}/restart-agent`, `/pull`, `/clean` | agent operations, forwarded to `:8081` |
| GET | `/api/cluster/backends`, `/api/cluster/gpu-metrics` | running backends; live GPU probe across nodes |
| POST | `/api/cluster/backends/start`, `/stop`, `/clear-cooldowns` | backend lifecycle |
| POST | `/api/cluster/suggest-placement` | hardware-fit recommendation |
| POST | `/api/cluster/discover`, `/propose` (`proposed_by` is the authenticated caller; a body field of that name is ignored), `/proposals` (the list), `/proposals/decide`; GET `/proposals/{id}` | node discovery and the propose/approve enrollment flow (`enroll_now` and `proposals/{id}/retry` were removed; re-enroll with a new bootstrap token) |
| POST | `/api/cluster/nodes/{node_id}/logs` | a node pushes its log batch (Loki push shape, optional gzip); node credential only, `{node_id}` must be the caller; `node` label overwritten with the verified id. `204` accepted, `400`/`413` drop the batch, `429` + `Retry-After` over the per-node budget (`NOO_LOGS_INGEST_BYTES_PER_MIN`, `NOO_LOGS_INGEST_REQUESTS_PER_MIN`), `503` Loki unavailable |
| POST | `/api/cluster/mint-join-key`, `/api/cluster/delete-tailscale-device` | tailnet join keys, device removal |
| GET | `/api/cluster/replication-status` | Postgres replication view |
| GET, POST | `/api/security/bootstrap-tokens`; POST `…/{id}/revoke` | bootstrap tokens for `noo enroll` |
| POST | `/api/cluster/bootstrap`, `/api/cluster/enroll-tailnet` | the enrolling node's first calls |
| GET | `/bootstrap`, `/bootstrap/prep`, `/bootstrap/apply`, `/bootstrap/deenroll`, `/bootstrap/fetch`, `/bootstrap/ca.crt` | the pull rail a node walks during enrollment |
| POST, GET | `/api/cluster/provision-bundle/{node}`, `…/status`; GET `/bootstrap/bundle/{node}`; POST `/bootstrap/bundle/{node}/applied` | signed provisioning bundles |
| PUT, GET | `/api/cluster/cli-asset/{name}`, `/bootstrap/cli/{name}` | CLI binaries served to nodes |
| GET | `/api/artifacts/manifest/{kind}/{name}` | artifact rail manifests (`gguf`, `modelfile`, `image`; `binary` is retired): `{size_bytes, sha256, data_path}`. The sha256 is cached by path, size and mtime; a file not yet hashed is hashed in the background, and a request that would wait more than ~8 s gets `202 {"status":"hashing","retry_after_secs"}` with `Retry-After` — ask again. `noo cluster sync-model-files` warms this before it queues the node jobs |


## Models

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/models/cached` | models cached per node |
| POST | `/api/models/cache`, `/api/models/pull` | pre-cache / pull a model on a node (streams progress) |
| GET | `/api/ollama/models` | what the Ollama backend has |
| GET, POST | `/api/terminal/backends`, `…/stop`; POST `/api/terminal/ollama/pull`; DELETE `/api/terminal/ollama/{model_name}`; POST `/api/terminal/ollama/create-claude-variant` | backend list/stop and Ollama model management |

## Jobs and scheduler (`routes/admin.rs`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/jobs/submit` (alias `/api/tasks/submit`) | `{job_type, payload, priority, backend, force_node, min_vram_gb, timeout_sec, max_retries, allow_queue_without_backend, expire_after_sec}`; a named `backend` that no healthy node is serving is refused 400 unless `force_node` or `allow_queue_without_backend` is set; job types: `inference`, `tool_exec`, `model_download`, `model_file`, `fetch_bundle`, `background_graph`, `background_cache` (node) and `test_run` (gateway) (`background_embed` is retired; `embed_batch` is created only by `POST /api/external/embeddings/jobs` and is refused here). **User tier** (also `noo_job_submit` on the user MCP door): `inference` only, an object payload up to 64 KiB, `force_node` / `min_vram_gb` / `allow_queue_without_backend` refused (`403`), `backend` one of `vllm`/`ollama`/`llamacpp`, priority capped at 5, `timeout_sec` at 600, `max_retries` at 2; 30 submits per hour per account (`429` with `Retry-After`). Every submit writes a `job_submit` audit row. `/api/tasks/submit` stays Operator+. A job still queued past `expire_after_sec`, or 24 h after submit, or of a type no node executes, is set `dead` by the scheduler janitor with an error starting `expired:`. A job pinned with `force_node` to a node that is not healthy waits without blocking the jobs behind it (`status_detail` says why) |
| GET | `/api/jobs`, `/api/jobs/history`, `/api/jobs/{job_id}` | queue, history, one job. Scoped by ACCOUNT (a job submitted from any session of `alice` is `alice`'s): a `user`-tier caller sees its own jobs plus unowned ones; Operator+ sees every job. An unreadable id is a `404` |
| DELETE | `/api/jobs/{job_id}` | cancel. Open to the User tier for the caller's own account's jobs; Operator+ may cancel any job. Another account's job, or an unowned fleet job, is a `404` to a User. Writes a `job_cancel` audit row (`job_cancel_denied` on a refusal) |
| POST | `/api/jobs/{job_id}/reprioritize` | change a queued job's priority. Operator+ only at the tier gate; the handler is also owner-scoped (`404` otherwise) |
| GET | `/api/scheduler/status` | running/paused, queue depth, active jobs, drained nodes |
| POST | `/api/scheduler/pause`, `/resume`, `/drain/{node_id}`, `/undrain/{node_id}` | scheduler controls |


## Knowledge base and graph (`routes/knowledge.rs`)

Served by the trellion add-on; every route answers `503` with
`{"error": …, "addon": "trellion"}` while it is disabled.

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/rag/query` | `{question` (or `query`)`, strategy: "hybrid"}` → answer, citations, `strategy_used`. Open to the User tier |
| POST | `/api/v1/rag/ingest`, `/api/v1/docs/ingest` | ingest a document. **Audience:** explicit `roles` (clamped to what the caller may tag; an over-reach falls back to `user:<account>`); otherwise a signed-in uploader gets `user:<account>` (no source rule or default widens it); a caller with no account (watched folders, Drive loop, heartbeat, cluster credential) gets the source rule, then `kb.source_roles`, then `kb.default_roles`, then the explicit `admin` tag. A document is never stored untagged. **Sources:** `text` is stored as text and is never read as a path. `source` names ONE file that must resolve (symlinks followed) under `tools.allowed_paths`, a watched-folder mount, the workspace or the watched-folder staging area, and never under the service's own secrets, PKI or config; otherwise it is refused with the allowed roots listed. URLs, directories and globs are refused (ingest does not fetch URLs, and takes one file per call): fetch the content and send it as `text`, or use a watched folder. `rag/ingest` takes JSON. `docs/ingest` takes `multipart/form-data` (`file`, optional `title`; UTF-8 text only, a binary file is `400`, use a watched folder) or JSON, up to 32 MiB, and is the one route the `ingest` scope opens. **Operation-backed:** `200` with the worker's reply if it finished within the wait, else `202` with an operation handle ([below](#asynchronous-operations-routesopsrs)) |
| POST | `/api/v1/rag/retag` | change which audience documents belong to. Operator+; body `{roles, match` (glob on `source_uri`) `or doc_ids, only_untagged?, limit?, apply?}`. A **dry run unless `apply` is `true`**; `roles` is clamped to what the caller could write itself (`not yours to tag into` otherwise) and may not be empty; `only_untagged` defaults true, send `false` (`--relabel`) to move already-tagged documents. An applied retag writes one `kb_retag` row to the security audit and a `{from, to}` entry in each document's `audience_history` (`noo rag retag`) |
| POST | `/api/v1/rag/deduplicate` | one-time page dedup |
| POST | `/api/v1/docs/hold`, `/api/v1/docs/unhold` | keep documents out of embedding and search (or release them). Operator+ only, in no add-on scope; body `{title_prefix` (a literal prefix) `or doc_ids, reason` (hold only, required)`, apply?}`. A **dry run unless `apply` is `true`**; answers `{count, applied, doc_ids` (first 50)`, status, message}`. Nothing is deleted. An applied call writes a `kb_hold` / `kb_unhold` row to the security audit (`noo rag hold`) |
| GET | `/api/v1/docs/held` | held documents: `{total, docs: [{doc_id, title, reason, held_at}], limit, offset}`. Operator+; query `reason`, `limit`, `offset` (`noo rag held`) |
| POST | `/api/v1/docs/purge` | **delete** the documents held under exactly `reason`, with their pages, chunks, embeddings and mentions. Irreversible. Operator+ only, in no add-on scope; body `{reason` (required, never empty)`, apply?}`. A dry run unless `apply` is `true`; answers `{count, deleted, doc_ids` (first 50)`}`. An applied purge writes a `kb_purge` row to the security audit (`noo rag purge`) |
| GET | `/api/v1/rag/status` | store health |
| GET | `/api/v1/docs` | ingested documents, newest first. A restricted caller sees only documents whose audience overlaps theirs (untagged ones are invisible to them); Operator+ items also carry `roles`, `provenance` and `audience_history_len`. Query: `limit` (200, max 2000), `offset`, `summary=1` (wraps the answer as `{docs, summary: {total, untagged, by_audience}}`), and the filters `untagged=1`, `audience=<tag>` (`user:*` = any personal tier), `match=<source_uri glob>`, `q=<title text>` |
| GET | `/api/v1/docs/{doc_id}` | one document: row, page count, first ~1000 characters. Operator+ also get `roles`, `provenance`, `audience_history` and the whole `metadata`. `400` for an id that is not a UUID; `404` for a missing document **and** for one the caller cannot read (identical) |
| POST | `/api/v1/ingest/scan` | scan watched folders and drives now (`?source=folders\|drives\|all`, default `all`; `400` on anything else); answers `{results}` |
| GET | `/api/v1/graph/stats`, `/entities`, `/entities/{entity_id}`, `/entities/{entity_id}/neighbors`, `/overview`, `/clusters/overview` | knowledge-graph reads (SQL-internal, no worker round-trip). `overview` takes `limit` (200, max 500), `entity_type`, `min_degree` (2) |
| GET | `/api/v1/graph/clusters/audit` | read-only audit of how each cluster mixes audience tiers, what a `{company, system}` reader sees of it, and untagged-document coverage (`?limit=` caps the per-cluster list, default 1000, max 5000). Needs an unrestricted audience (admin or `kb:unrestricted`); anyone else gets `403` |
| POST | `/api/v1/graph/entities/resolve` | resolve names to entities |
| POST | `/api/v1/graph/recluster`, `/extract-relations`, `/navigate`, `/traverse` | Intelligent-tier graph work. Operator and above, except `/navigate` and `/traverse`, which a User holding the `graph` scope (`read` + `graph`) may also call, audience-scoped; a plain `read` account gets `403`. **Operation-backed:** `200` with the result if it finished within the wait, else `202` with an operation handle ([below](#asynchronous-operations-routesopsrs)). `recluster` always answers `202` (a run is minutes) |
| POST | `/api/v1/graph/explain-path`, `/semantic-search`, `/search-clusters`, `/classify-intent`, `/recall-traversals` | Intelligent-tier graph calls that answer inline (no operation). Operator and above, except `/explain-path`, `/semantic-search`, `/search-clusters` and `/classify-intent`, which a User holding the `graph` scope may also call (`/recall-traversals` stays Operator and above; a plain `read` account gets `403` on all of them). For a restricted caller `navigate` and `explain-path` return only edges backed by a single readable document and carry no evidence text, page ids or page numbers (an edge seen more than once is withheld; an `explain-path` route that cannot be shown is `found: false` with `reason: route_not_provable_for_audience`), and `search-clusters` omits `parent_cluster_id`, `level` and `generation`. Without the `trellion_intel` add-on: `503 {error, addon: "trellion_intel", state, capability, hint}`. A restricted caller's audience is resolved server-side and passed down as `roles` (a client-supplied `roles` is dropped); a reply the worker did not stamp as audience-filtered is `503`, never served |
| GET | `/api/v1/graph/prune/staged` | the prune staging area (entity names, newest first): `limit` (200, max 1000), `reason`, `include_restored`. Answers `staged`, `counts`, `staged_edges`, `edge_counts` |
| POST | `/api/v1/graph/prune/restore` | bring staged rows back. **Operator and above** for both routes (a User gets `403`). Body is one of `{staging_ids}` (100 per call), `{edge_staging_ids}` (500 per call; both lists in one call merge), or `{run_id}` to bring back every *entity* one run staged (`entq-…` from `entity-cleanup`, or a prune run id; 1-64 letters, digits, `-`, `_`; 500 per call, and the answer's `remaining` says whether to call again; edges between two junk entities are restored too). `noo graph prune restore --run <id>` loops it. Per row the status is `restored`, `already_restored`, `not_found`, `refused` or `error`. **Refused (row stays staged):** a row whose payload has no `user_id` key at all (`this row does not record its owner; it is not restored`; stamp it by hand), and a row staged for an erased user or an account erased since it was staged (`this row was set aside for a user who has been erased; it is not restored`). A database failure answers a fixed `the restore could not complete; see the gateway log` (the detail never quotes row values). Embeddings and graph signals are not restored; they regenerate |
| POST | `/api/v1/graph/entity-cleanup` | **Admin only**, audited. **An apply needs a person's own credential**: a harness credential (the MCP operator door, `mcp-external`, a node harness, an agent run) may preview but gets `403` on `apply: true`, naming `noo graph entity-cleanup --apply` (the type's `human_only_apply` flag), and any delegated or exchanged credential (one carrying `act`) is refused outright. Finds the junk entities the extractor now refuses (`a`, `x_t`, `theta`, `0.003`) and, when the body says `"apply": true`, stages each into the prune staging area (reason `junk_entity`, restorable with `prune/restore` for 30 days) and deletes it, at most `max_delete` (default and ceiling 5000) per run. Body `{apply?: bool, examples?: 0-200 (20), max_delete?: 1-5000}`; **a dry run unless `apply` is the boolean `true`** (any other type is `400`). **Operation-backed** (type `graph.entity_cleanup`): `200` with the report if it finished within 3 s, else `202` with a handle. The report: counts (`scanned`, `junk`, `edge_rows`, `mention_rows`, `cluster_rows`, `by_reason`, `by_type`), `examples` (name, type, edges, mentions, clusters; most connected first), and on apply `staged`, `skipped_over_cap`, `run_id`. An apply writes a `graph_entity_cleanup` audit row (`started`) **before** anything is deleted and a second one (`ok`/`busy`/`failed`, counts and run id, never a name) after. Refused `409 busy` while graph prune or a recluster runs; `503` if the audit row cannot be written (nothing is deleted). Needs the trellion build that ships the cleanup, else a clear "upgrade" error |

## Saved walks (`routes/walks.rs`)

A signed-in user's `navigate`, `traverse` and `rag` walks are saved by the
worker as that user's own **threads**. These routes read them back. Without
the trellion add-on `stats` and the admin view answer `503`; recall needs the
`trellion_intel` add-on (the same explained `503` as the other Intelligent-tier
graph routes). The MCP tool is `noo_walks_recall`.

| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | `/api/v1/walks[?q=][&top_k=]` | any signed-in account | the caller's **own** threads, verbatim. With `q` the nearest to the question, revalidated against the graph and documents *now* for the caller's audience (an unreadable step, a snipped edge or a deleted fact drops a walk); without, the most recent. `top_k` default 5, clamped 1-50. Another user's threads are never returned, whatever the role; there is no parameter that names one |
| GET | `/api/v1/walks/{id}` | any signed-in account | one of the caller's own threads. Someone else's id and a missing id give the same answer |
| GET, PUT | `/api/v1/walks/settings` | any signed-in account (open to the User tier) | the per-account switch `walks.save_threads`, **on by default**. `GET` answers `{save_threads, default: true, key}`; `PUT {"save_threads": false}` stops *new* saves and deletes nothing. The setting is stored per account and erased with it |
| GET | `/api/v1/walks/stats[?user=]` | Operator+ | **counts only**: by kind (`thread`, `simulated`, …) and status, per account active/total (top 200), and `opted_out_accounts`. Never a query, path or entity name |
| GET | `/api/v1/admin/walks?user=<account>[&limit=]` | **Admin only** | that account's threads, verbatim (`limit` default 50, clamped 1-200). Every view writes one `walks_admin_view` row (warning) to the security audit (who viewed whose, how many, any delegation, never the content) **before** the content is returned: if the audit row cannot be written the view is refused `503` and nothing is served. Operators and credentials without an account get `403` (operators have `stats`); a missing `user` is `400` |

Credentials with no account (cluster HMAC, unsigned) get `403` on the
settings routes; recall and settings act only for the verified account, never
a name in the request.

## Asynchronous operations (`routes/ops.rs`)

A request that can last minutes must not *be* a request: an MCP client, a proxy
or a CLI gives up first, and the user is told the gateway is unreachable while
it is working. The gateway therefore runs such work as an **operation**: a row
in `noo_ops` with an id, run in a detached task, polled by id.

**The long routes are operation-backed.** `POST /api/v1/graph/recluster`,
`/graph/extract-relations`, `/graph/navigate`, `/graph/traverse`,
`/graph/entity-cleanup`, `/api/snapshots/consolidate`, `/api/v1/rag/ingest` and
`/api/v1/docs/ingest` all do the same thing: start an operation, wait up to that type's
`default_wait`, then answer

- **`200`**, with the result in exactly the shape (and status) the route has
  always answered, if the run finished inside the wait; or
- **`202`**, with a handle `{op_id, type, status, poll, poll_interval_ms,
  hint}`, if it did not; or
- if the op ended some other way while the route waited: the worker's own
  body at its recorded status for a **failed** run (`500` when none),
  **`409`** `{"error": "the operation was cancelled while this request waited
  for it", op_id}` for a **cancelled** one, and **`410`** `{"error": "the
  operation's result has expired", op_id}` for one whose result already
  expired.

A type that slows down later therefore starts answering with handles by itself,
and no request is ever held for a whole run. **Every caller must handle both
answers.** `?wait=<seconds>` (at most 25) overrides the type's default wait for
one request; `?wait=0` always returns the handle.

| Type | Route | Default wait | Run limit | One at a time |
|---|---|---|---|---|
| `graph.recluster` | `/api/v1/graph/recluster` | 0 s (always a handle) | 930 s | yes |
| `graph.extract_relations` | `/api/v1/graph/extract-relations` | 3 s | worker timeout + 30 s | no |
| `snapshots.consolidate` | `/api/snapshots/consolidate` | 3 s | 600 s | no |
| `graph.navigate` | `/api/v1/graph/navigate` | 12 s | worker timeout + 30 s | no |
| `graph.traverse` | `/api/v1/graph/traverse` | 12 s | worker timeout + 30 s | no |
| `rag.ingest` | `/api/v1/rag/ingest` | 3 s | worker timeout + 30 s | no |
| `docs.ingest` | `/api/v1/docs/ingest` | 3 s | worker timeout + 30 s | no |
| `graph.entity_cleanup` | `/api/v1/graph/entity-cleanup` | 3 s | 630 s | no (the worker's prune lock serialises applies) |

`GET /api/v1/ops/types` lists them live (`type`, `route`, `timeout_secs`,
`default_wait_secs`, `wait_setting`, `poll_interval_ms`, `exclusive`,
`admin_only`, `human_only_apply`, `retry_safe`, `cancel`, plus a top-level
`max_wait_secs: 25`). "Worker timeout" in the table is `NOO_WORKER_TIMEOUT_SECS`
(default 120 s). The default waits are settings
(`NOO_OPS_WAIT_<TYPE>_SECS`, e.g. `NOO_OPS_WAIT_GRAPH_NAVIGATE_SECS`), hot-reloaded
within ~15 s from `noo_settings` (admin: `POST /api/settings/flags/set`) or set
in the environment; see [config.md](config.md#asynchronous-operations).

### The generic API

| Method | Path | Does |
|---|---|---|
| POST | `/api/v1/ops` | `{type, params}` → `202 {op_id, status, poll, poll_interval_ms}`; never waits. `params` is the body the type's route takes (a JSON object, else `400`). An unknown `type` is `400` and lists the known ones |
| GET | `/api/v1/ops/{id}[?wait=<s>]` | status, `progress`, and once finished the `result` (plus `result_status`, the status the route would have answered) or `error`. `wait` (≤ 25 s) long-polls until it finishes. A malformed id is `404` like an unknown one |
| DELETE | `/api/v1/ops/{id}` | cancel (see below) |
| GET | `/api/v1/ops[?mine=1][&status=][&limit=]` | `{operations, count}`: your operations, newest first, without results (`limit` default 50, clamped 1-100; `status` must be one of the six below, else `400`). An admin sees everyone's unless `mine=1` (`1`, `true` or `yes`) |
| GET | `/api/v1/ops/types` | the registered types, their route, waits, limits and cancel semantics |

`status` is `queued`, `running`, `succeeded`, `failed`, `cancelled` or
`expired`. A failed op keeps the worker's own body in `result` when there was
one, and `retry_safe` says whether resubmitting is harmless.

- **Authorisation.** Starting a type needs exactly what its route needs: the
  start asks `auth::requester_allows` about the type's own route, so a User-tier
  token that gets `403` on `POST /api/v1/graph/recluster` gets `403` on
  `POST /api/v1/ops {type: "graph.recluster"}`. Gates the route's handler
  applies itself (the Intelligent-tier add-on gate, the knowledge-base audience
  filter) are in the shared function the op runs. A type may be stricter than its
  route's front-door tier: `graph.entity_cleanup` is `admin_only` and `human_only_apply` (`GET
  /api/v1/ops/types` says so), so an Operator, a User, a controller service
  without an account, a worker-delegated agent token and an identity-exchange
  (`key:<consumer>`) token, even ones acting for an Admin (any credential
  carrying `act`), are all refused `403` at start, through the route and through
  `POST /api/v1/ops` alike. A caller with no account that is not a controller
  service is refused `403` for every type.
- **Identity.** An op runs as the account that started it, never as the
  gateway: the audience is resolved from that account when the op runs, and the
  detached task signs worker messages as that account. A restricted user's
  `graph.navigate` therefore returns only what they may read, exactly as the
  synchronous route did.
- **Visibility.** Only the owner (and an admin) can read, list or cancel an op.
  Anyone else gets `404 {"error": "no such operation"}`, byte-identical to an id
  that never existed. A caller that came through an MCP consumer sees only that
  consumer's ops, and an agentic run's delegated token is bound to its RUN (`harness` `worker:<run id>`, a random id minted per turn and shared by every tool call of that run): it can start an op in one tool call and follow or cancel it in a later one, and no other run, concurrent or later, sees it. A delegated token can only start an op whose route it could call directly (`worker_delegation::route_allowed`), so `rag.ingest` is refused to it through `POST /api/v1/ops` exactly as on its own route. The controller's own services (no account) own NULL-owner ops,
  visible to admins and to each other.
- **Concurrency.** `graph.recluster` is exclusive (the worker refuses a second
  concurrent run). A second start by the **same** account *joins* the run in
  flight (same `op_id`, `joined: true`, nothing new started). Another account's
  run in flight is answered as the worker always did: `200 {"status":
  "already_running"}` from the route, `409` from `POST /api/v1/ops`; the other
  account's id is not disclosed. An account may have at most 8 live ops
  (`NOO_OPS_MAX_ACTIVE_PER_OWNER`, 1-1000); more is `429`. A cancelled op keeps its slot until its
  type's run limit has passed (its worker run may still be going), and the count and the
  insert are one transaction under a per-account advisory lock (`pg_try_advisory_xact_lock`: a start
  that loses the race is `429`, it never parks a pool connection), so concurrent starts cannot overshoot.
- **Cancel.** Stops the gateway-side wait and aborts the detached task, and says
  so honestly: `cancel: {gateway_aborted, worker_stopped: false, note}`. A
  worker run already underway is **not** stopped (a recluster finishes; an
  ingest may still land). Cancelling a cancelled op is `200`; a finished op is
  `409`, and so is an op running on another gateway instance (only the instance
  holding the run can stop its wait).
- **Restart.** A gateway restart ends its detached tasks. At boot every live op
  of that instance is failed (`gateway restarted…`, with `retry_safe`); the
  sweeper fails ops whose runner stopped heartbeating (another instance that
  died). One gateway never fails another's live run: live runs are touched
  every 30 s. The instance id is `NOO_GATEWAY_INSTANCE` or the hostname.
- **Erasing an account.** Work already handed to a worker finishes whatever the
  gateway does, so `POST /api/security/users/{name}/erase` (not a dry run) is
  **refused with `409` and a `Retry-After`** while the account has a write-side
  operation (every type except `graph.recluster`) live, or with an open `worker_may_run_until`
  window: cancelled, or `failed` by a gateway restart, a lost runner or the supervisor timeout (the
  worker may still be mid-write). The message and header say when to retry; the wait
  is bounded by the type's run limit. The first refusal marks the account
  **erase-pending** (table `noo_ops_erase_pending`, persisted, so it holds across
  gateways and restarts): from then on every new operation start for it is refused with
  `423`, so a caller (or its MCP consumers and agents) that keeps starting writes cannot
  starve the erase. The successful erase clears the mark; the mark expires on its own after
  twice the longest run limit, and an admin can clear it early with
  `DELETE FROM noo_ops_erase_pending WHERE user_uuid = (SELECT user_uuid FROM noo_users WHERE username = '<name>')`.
  Only operation starts are refused; the account's other write routes are not.
  The check, the mark and the delete run under the account's op lock, so no start can slip in;
  read-side live operations are aborted by the erase; a refused erase (for example the last admin)
  aborts nothing. Every write-side adapter also re-checks that its own op row still exists
  immediately before it writes, so an op queued before an erase (or on another instance) does not
  write after it, `keep_account` included.
- **Retention.** Results are kept `NOO_OPS_RESULT_TTL_SECS` (default 24 h,
  clamped to 1 minute .. 30 days) after the op finishes, and never less than
  the type's worker window. Then the payload is cleared and a poll answers
  `status: "expired"`; a day later the row is deleted (the sweeper runs every
  30 s). A result over 8 MiB is a failure, not a truncated success. Stored
  `params` over 16 KiB are replaced by a marker, and ingest `params` are
  stored without the document text (an allow-list: `title`, `source`,
  `source_uri`, `roles`, `force`, `persona_id`). Right-to-be-forgotten erases a user's ops (`noo_ops` is an
  erase target).

From a terminal: `noo ops`, `noo ops show <id> --wait`, `noo ops cancel <id>`;
`noo graph recluster` and `noo graph entity-cleanup` start an op and follow it. From an MCP client:
`noo_op_start`, `noo_op_status` (long-poll with `wait`), `noo_op_cancel`,
`noo_op_list`; the long tools themselves return the result or the handle.

## Memory and conversations (`routes/memory.rs`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/memory/search` | semantic search over conversation memory (`noo_memory_search`) |
| GET | `/api/memory/status`, `/health`, `/storage-stats`, `/stats/{user_id}`, `/relationships/{record_id}` | memory reads. `/stats` is scoped by name (`403`); `/relationships` is scoped by the entry's conversation owner — an unreadable source id is a `404` and unreadable neighbours are dropped from the list. `/storage-stats` is an aggregate counter, global |
| POST | `/api/memory/cleanup`, `/api/memory/batch-index` | prune old conversations; index unembedded entries |
| POST, GET | `/api/memory/embed/start`, `/status`, `/stop` | the background embedding worker |
| GET | `/api/conversations`, `/api/conversations/{conversation_id}`, `/with-preview`, `/stats/tools`, `/stats/overview`, `/feedback/stats`, `/feedback/export/dpo` | conversation reads and the DPO export |
| POST | `/api/conversations/{conversation_id}/feedback` | rate a turn |

## Recall (`routes/recall.rs`)

Episodic recall, served by trellion. `/api/v1/recall/…` is canonical;
`/api/v1/video-memory/…` is the same set under its older name, deprecated
(marked so in the OpenAPI spec) and removed in the release after 0.6.0.

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/recall/search`, `/archive`, `/lifecycle`, `/refresh` | search; archive; run the lifecycle pass; refresh |
| GET | `/api/v1/recall/videos`, `/archive-status`, `/lifecycle-stats`, `/lifecycle-preview`, `/prominent`, `/status` | reads |

Delegated to the worker (`worker.recall.*`); `503`-style "worker unavailable"
answers when it does not reply.

## Temporal graph and snapshots (`routes/temporal.rs`, `routes/snapshots.rs`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/temporal/facts`, `/evolution`, `/user-profile/{user_id}`, `/agent-self`, `/projects` | bi-temporal graph reads. A `type = 'user'` subject is per-person and scoped (`403` for somebody else's); every other subject type is the shared brain and global by design |
| POST | `/api/temporal/adaptations` | record an adaptation edge |
| GET | `/api/snapshots`, `/api/snapshots/{snapshot_id}`, `…/curriculum` | consolidation snapshots |
| POST | `/api/snapshots/diff` | diff two |
| POST | `/api/snapshots/consolidate` | run consolidation now. **Operation-backed:** `200` when the snapshot is complete within the wait, else `202` with an operation handle that follows the snapshot to `complete` or `failed` (`GET /api/snapshots/{id}` still reports it) |

## Automation (`routes/intelligence.rs`, `routes/ui.rs`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/heartbeat/tasks`, `/status`, `/history`, `/actions`, `/artifacts`, `/tasks/{task_id}/artifacts` | heartbeat scheduler reads |
| POST | `/api/heartbeat/tasks`, `/api/heartbeat/schedule` | create a task. A task that deletes data written by an MCP door, agent or delegated credential is not written: it answers `proposal: true, task_created: false, proposal_id` and waits in the user-proposal queue (see Tasks that delete data). `GET /api/heartbeat/tasks` carries `guard` per task: `destructive`, `destructive_why`, `authorised_by`, `authorised_at`, and `apply` (`preview` / `apply`) for `entity_cleanup` |
| PUT | `/api/heartbeat/tasks/{task_id}/toggle` | enable / disable (enabling a destructive task from a door is a proposal; disabling is always direct) |
| PUT | `/api/heartbeat/tasks/{task_id}/schedule` | change only the cron `schedule` (operator-only; body `{schedule}`; `400` carries the scheduler parser's reason, `404` unknown task; `next_run` clears only if the schedule changed; a destructive task edited from a door is a proposal) |
| DELETE | `/api/heartbeat/tasks/{task_id}` | remove |
| GET, POST | `/api/heartbeat/review-existing`, `/api/heartbeat/review-existing/approve` | tasks and saved recipients that predate the task guard and have no recorded person; the POST (a person only) records the approver |
| POST | `/api/heartbeat/tasks/{task_id}/run`, `/api/heartbeat/reload` | run now (`403` from a door for a task that deletes data); reload the schedule (also re-reads the timezone) |
| GET | `/api/autonomy/status`, `/api/autonomy/audit` | locations and their audit trail |
| GET | `/api/autonomy/decisions` | what the disarmed locations *would* have done (`?outcome=would` by default; `fired`, `error` or `all`) |
| POST | `/api/autonomy/locations`, `/api/autonomy/locations/{name}/toggle`, `/api/autonomy/enable`, `/api/autonomy/disable` | manage locations |
| GET, POST | `/api/activities`; POST `…/{id}/progress`, `/link-task`, `/complete`; PUT `…/{id}/status` | agent activities |
| GET | `/api/agent/loops` | managed loops |
| GET, POST, DELETE | `/api/proactive/status`, `/rules`, `/history`, `/rules/{rule_id}` | the proactive loop |
| GET, POST | `/api/approval/pending`, `/stats`; POST `…/{request_id}/approve`, `/deny`, `/decide` | exec-approval queue. `pending` is scoped to the requester for `user` tier (unbound rows stay operator-only) and echoes `scope`; `/stats` is four aggregate counts, global; approve/deny/decide need a named Operator+ **person** (an ordinary login: a worker-delegated tool token, harness or MCP-door key, service identity or non-user account gets 403) |
| GET | `/api/exec-approval/status` | current mode |

## Agents, workflows, skills, tools (`routes/agents.rs`, `routes/peers.rs`, `routes/ui.rs`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/agents/roles` | agent roles (backends: `/api/cluster/backends`) |
| POST | `/api/agents/collaborate` | `{prompt|task, roles?, wait?}` — one task per role, as the caller, on the nodes holding their models, all in one thread; answers `results` by role once they settle (or `wait` seconds pass), plus `task_id` and `thread_id` (`noo agents collaborate`) |
| GET, POST | `/api/agents/messages`; GET `…/{id}`, `/api/agents/threads`; POST `…/{id}/ack` | agent-to-agent messages. A User-tier token may send (`POST /api/agents/messages`) and ack (`POST …/{id}/ack`), and only those two writes (collaborate, trust and keys stay Operator+): `from` must be an identity the caller owns, broadcast is refused, posting into an existing thread needs a seat, the recipient must exist and be the same owner or have trusted the sender, and ack needs to own the recipient address (a connection `user/label` cannot ack mail addressed to the bare account `user`; a database error on the thread-seat check is `500`, never an admit) (a non-privileged GET lists what the credential owns: an account reads its connections' mail too, a connection only its own; sealed and signed by the CONTROLLER with `NOO_AGENT_REVIEW_KEY` when set — the signature attests the gateway authenticated the sender it names, it is not the sender's own signature) |
| GET | `/api/agents/archive`; `/api/agents/archive/{month}` | the agent-mail cold-storage archive (Operator+; below that `403`). The list returns the files with month, row count and size. `{month}` is `YYYY-MM` or the archive file name (never a path); the export returns that month's rows with bodies still sealed, or opened with the cluster review key under `?decrypt=true`, which writes an `agent_archive_decrypt` audit row first and is refused if it cannot be written (`503` when the cluster has no review key) |
| GET, PUT | `/api/agents/keys/{agent}`, GET `/api/agents/keys/review` | agent keys |
| GET, POST | `/api/agents/trust` (`?agent=`), POST `/api/agents/trust/remove` | the exceptions that let an identity outside the owner address an agent; the default (every identity the owner holds) is a rule, not rows |
| GET | `/api/agents/presence` | which windows (connections) are online; an operator may list anyone, anyone else lists their own account and is refused (not emptied) for another's |
| POST | `/api/agent/run` | run an agent |
| GET | `/.well-known/agent.json` | A2A agent card (public) |
| GET, POST, DELETE | `/api/agents/peer/`, `/register`, `/{agent_id}`, `/{agent_id}/task`, `/for-capability/{capability}` | peer agents; `register` and `DELETE /{agent_id}` need Operator+, an internal service, or that agent's own peer token; `/{agent_id}/task` needs Operator+ or an internal service — a peer never tasks through the gateway, not even itself (it sends an agent message, which is recorded) |
| GET, POST | `/api/workflows`, `/api/workflows/run` | predefined pipelines |
| GET | `/api/persona/`, `/api/persona/{persona_id}` | personas |
| POST, GET | `/api/coding/task`, `/api/coding/tasks`, `/api/coding/tasks/{task_id}` | coding-task history; execution refuses — coding is done by an external Claude Code through the MCP door |
| GET, POST | `/api/skills/list`, `/api/skills/{skill_name}/info`, `/api/skills/{skill_name}/run`, `/api/skills/rescan` | containerised skills |
| GET, POST | `/tools/list`, `/tools/select`, `/api/tools/registry/raw`, `/api/tools/nodes/{node_id}` | the tool registry; `select` previews which tools a prompt would get |
| POST, GET | `/api/tools/browser/sessions/start`, `…/{session_id}/stop`, `/api/tools/browser/sessions`, `/action`, `/status` | the browser tool |
| GET, POST | `/api/prompt-skills`, `/api/prompt-skills/{name}` | prompt skills (POST creates an evolved skill) |
| PUT | `/api/prompt-skills/{name}` | rewrite an evolved skill; a core skill is 400 `core skills are never mutated` |
| POST | `/api/prompt-skills/{name}/retire`, `/api/prompt-skills/{name}/fitness` | retire an evolved skill; adjust its score |
| GET | `/api/prompt-skills/proposals` | operator or admin: promotion proposals for runtime skills (`?status=`, `?limit=`); files one for any runtime skill that has none on its current text |
| POST | `/api/prompt-skills/proposals/{id}/decide` | a person only (operator or admin login; agent, harness, MCP-door and service credentials get 403): body `{decision: "promote"\|"reject", reason?}`; 409 when the skill's text changed since the proposal |
| POST | `/api/prompt-skills/evolve` | LLM-driven create/mutate, served by the evolve add-on (503 + refusal without it); proposal by default, `apply: true` writes |

The four skill writes are also opened, and only they, by the add-on control scope `prompt_skills:write`.
| POST | `/api/v1/device/{action}` | companion sensor proxy (`camera_capture`, `location`, `clipboard`, `screenshot`, `ambient_audio`, `battery_status`) |

The loop itself can message: `noo_agent_message`, `noo_agent_inbox` and
`noo_agent_ack` are native tools on every agent loop, wherever it runs.
They use these same routes' rules — the sender is the person the loop
runs for, the node is where it runs, and the harness column is the
credential class (`node:<id>` on a node-hosted loop, `loop:<controller>`
on the gateway's own). Broadcast is refused; a thread needs a seat.

## Channels and voice (`routes/communication.rs`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/channels/status` | configured channels (`telegram`, `google_chat`, `whatsapp` outbound) |
| POST | `/api/channels/send`, `/api/channels/test` | send a message; send a test |
| GET | `/api/channels/{channel}/recipients`, `/api/channels/{channel}/messages` | known recipients; recent inbound |
| GET, POST, PUT, DELETE | `/api/channels/saved-recipients`, `…/{recipient_db_id}` | address book. Rows carry an `owner` (migration `071`); `owner: null` is the shared book — readable by everyone, writable by Operator+ only. A `user`-tier caller reads its own + shared and writes only its own (`404` otherwise) |
| GET | `/api/alerts/clients` | connected alert WebSocket clients |
| POST | `/api/voice/transcribe`, `/api/voice/transcribe/detailed`, `/api/voice/synthesize`; GET `/api/voice/voices`, `/api/voice/status` | STT / TTS through the configured providers |

## Users, security, settings (`routes/users.rs`, `routes/settings.rs`, `routes/admin.rs`)

| Method | Path | Purpose |
|---|---|---|
| GET, POST | `/api/security/users`; PUT `…/{username}/password`; POST `…/disable`, `/role`, `/scopes`, `/org`, `/roles`, `/roles/revoke` | user management |
| POST | `/api/security/users/{username}/erase` | right to be forgotten. Body `{dry_run?: bool (default **true**), keep_account?: bool}`: a bare call only previews the per-store row counts and the knowledge-base plan (personal documents go, shared ones are scrubbed). `dry_run: false` snapshots every matched row into the erasure archive and deletes it all in one transaction, removes the user's upload files (when nobody else uploaded the same bytes) and audits it (`user_erase`); `keep_account` wipes the data but keeps the login. Refused: a target above the caller's tier (`403`, also on the dry run), the configured operator account (`NOO_ADMIN_USER`/`NOO_OPERATOR_USER`, `400`), the last admin (unless `keep_account`). **`409` + `Retry-After`** while the account has a write-side [operation](#asynchronous-operations-routesopsrs) live or within its worker window; that refusal marks the account erase-pending, after which every new operation start for it is `423` (see *Erasing an account*). A refused erase is audited (`user_erase_refused`) |
| GET | `/api/security/erasure-archive` | what the erase archive holds: row and run counts, the age of the oldest copy, the 30-day retention window (`retention_days`), and whether the daily purge is running (Operator+; an authenticated caller below Operator gets `403`, no credential `401`) |
| GET, POST | `/api/security/users/{username}/links`; POST `/api/security/channel-links/unlink` | channel identity links |
| POST, GET | `/api/security/users/propose`, `/api/security/user-proposals`, `…/{id}`; POST `…/{id}/decide` | User files, Operator decides |
| GET, POST | `/api/security/teams`; DELETE `…/{team}`; GET, POST `…/{team}/spaces`; POST `/api/security/channel-team-links/unlink`; GET, POST `/api/security/orgs` | teams, orgs, space links |
| GET, POST | `/api/security/kb-rules`; GET `/api/security/role-grants` | knowledge-base access rules and grants |
| GET, POST | `/api/security/posture`; POST `/api/security/posture/profile` | posture gates — POST needs an operator client certificate plus a certificate-bound Admin token; an app login is refused however privileged |
| GET, POST | `/api/security/service-keys`, `…/self`; GET `…/scopes`; POST `…/self/revoke`, `…/{consumer}/revoke`, `/revoke-and-disable`, `/rotate`, `/retire`, `/quota` | service keys (`retire` finishes a rotation by deactivating the superseded key once the new one has been seen) |
| GET | `/api/security/audit-history`, `/api/security/audit/stats`, `/api/security/audit/verify`, `/api/security/violations`, `/api/security/pki/status`; POST `/api/security/pki/rotate-expiring` | audit and PKI (`audit/verify` recomputes each audit row's hash under its epoch's key, checks the hash chain for deleted or reordered rows, and names what fails; Operator+. Its `chain` section reports `checked` (false with a `note` when it could not judge), the chained and pre-chain row counts, rows removed by retention, the `head` `{seq, chain_hash}`, an `export` section comparing that head with the signed heads the gateway appends every 15 minutes to `/data/audit-archive/chain-head.jsonl` (`checked`, `note`, `last_exported`, `regression`; a database head older than an exported one is a `problems` entry and verdict `fail`, no export yet is `checked: false`), and the `first_break`) |
| GET | `/api/security/audit/list` | read the security audit log, newest first. **Operator+** (a lower tier gets `403`). Query: `since` (RFC 3339 time or a window `30m`/`24h`/`7d`/`2w`; anything else is `400`), `event_type` and `actor` (exact), `limit` (default 100, max 500), `cursor` (the previous page's `next_cursor`; a forged one is `400`). Answers `{events, count, next_cursor}`; an event has `id`, `timestamp`, `event_type`, `severity`, `actor`, `resource`, `outcome`, `request_id`, `details` (where `source_ip` and, inside an agent turn, `conversation_id` are recorded), `chain_seq`, `entry_hash`. Listing does not verify. Each read writes an `audit_log_read` row (after the read, so it does not list itself) (`noo security audit list`) |
| GET, POST | `/api/users`, `/disable`, `/propose`, `/proposals`; `/api/kb/grants`, `/rules`, `/teams`, `/teams/create`, `/teams/delete` | older short forms of some of the operations above |
| GET, PUT | `/api/settings`, `/api/v1/settings`; GET `…/export`, `/api/v1/settings/preference` | the settings snapshot |
| GET, POST | `/api/settings/flags`, `/api/settings/flags/set` | behavioural flags ([config.md](config.md#behavioural-flags)) |
| GET, PUT | `/api/config`, `/api/config/{section}` | read / deep-merge into `noomesh.yaml` (`noo config get/set`). Reads are Operator+ and redact any credential-shaped key's value (`*_key`, `*token*`, `*secret*`, `*password*`; names ending `_env` or `_tokens` are exempt). A `PUT` (here and on `/api/settings`) that carries a non-empty string under a credential-shaped key at any depth is refused `422` with the remedy `noo security secrets rotate <NAME> --set-from-stdin` |
| GET | `/api/v1/settings/browse` | browse the server's folders |
| GET, POST, DELETE | `/api/v1/settings/user-dirs` | watched-folder management (adding a `writable` folder is admin-only) |
| GET | `/api/v1/settings/restart-status` | restart-needed flag |
| GET | `/api/usage/summary` | token usage by month / dimension — `group=node|model|backend|source|user|consumer|day` (`noo usage`). An operator report: Operator+ sees the install, a `user`-tier caller sees only its own consumption at every grain. The response echoes `scope` (null = the whole install) |
| GET | `/api/usage/me` | one person's spend for the period (`period=day|week|month`, default the allowance's period, else `month`; Operator+ may name `user=`): `node`, `cloud` and `harness` (one entry per kind) as separate columns, each with `prompt_tokens`, `completion_tokens`, `total_tokens`, `requests`, `cost_usd`, `unpriced_tokens` and a breakdown (`by_node`, `by_provider`, `by_model`). A row is in exactly one column: backend `cloud-*` is cloud, a `harness_kind` (backend `harness:<kind>`) is that kind, anything else is node. `spent` is the one budget number across them; `allowance` is `{period, limit, spent, remaining}` or null (`noo usage me`). `cost_usd` prices tokens by the longest model-name prefix in the `NOO_MODEL_COST_USD_PER_MTOK` setting (a JSON object of prefix → USD per million tokens); reported, never enforced |
| GET, PUT, DELETE | `/api/users/{username}/allowance` | a person's standing token allowance: `PUT {tokens, period?}` (`period` `day`, `week` or `month`, default `month`) sets it and `DELETE` removes it (Admin only, audited); `GET` returns `{user, allowance: {period, limit, spent, remaining} | null}` to an Admin or the person (`noo security user allowance`) |
| GET / POST | `/api/mcp/servers` | the external MCP server registry (`noo mcp server list/add`); operator role |
| GET / PUT / DELETE | `/api/mcp/servers/{id}` | one server: spec, audience, placements, discovered tools (`noo mcp server show/enable/disable/remove`) |
| PUT / DELETE | `/api/mcp/servers/{id}/placements/{node}` | which registered node hosts or dials it (`noo mcp place/unplace`) |
| POST | `/api/cluster/nodes/{node}/mcp/{id}/tools` | node rail: the hosting node's discovery report (catalog replaced whole) |
| GET | `/api/logs/status`, `/query`, `/containers`, `/docker-stats`, `/node/{node_id}/{container}`; POST `/api/logs/tail`, `/api/logs/errors`, `/api/logs/search` | logs: `search` is Loki-only (the gateway builds the LogQL); `tail`/`errors` are Loki-backed with a node-agent scan fallback and say `backend`; every route Operator/Admin only |
| GET | `/api/cache/stats` | Redis cache stats |
| GET, POST | `/api/db/migrations`, `/api/db/migrations/apply` | the mesh migration runner (`noo db`) |
| POST | `/api/cleanup/heartbeat-runs/restore` | undo one `heartbeat_retention` prune (the prune is that heartbeat task, run on demand via `/api/heartbeat/tasks/{task_id}/run`) |
| GET, POST | `/api/tests/status`, `/api/tests/run` | the `test_run` gateway job |
| GET, POST | `/api/mesh/status`, `/operations`, `/restart`, `/rebuild`, `/stack-rebuild` | stack operations via the host spool |
| GET | `/api/metrics/query`, `/api/metrics/range`, `/api/metrics/discover`, `/api/alerts/list` | Prometheus passthrough: instant query, range query (11,000-point and 100-series caps), metric/label discovery, and alert rules merged with Alertmanager state (Operator+, read-only) |
| POST | `/api/monitoring/grafana-session` | open Grafana as yourself: mints a short-lived Grafana login token for the caller's live account (any tier; a disabled account is refused) |
| GET, POST | `/api/grafana-ds/prometheus/{*path}`, `/api/grafana-ds/loki/{*path}` | Grafana's data sources through the gateway, the viewer's tier enforced per query; Grafana's service leaf only, no bearer opens them |
| GET | `/api/addons/{addon_id}/cli-piece`, `/console-piece` | an add-on's own `noo` commands / console diagram slots, validated by the gateway. `404` unknown add-on or no piece, `503` add-on disabled or unlicensed, `502` no answer or an invalid piece |
| GET | `/api/mcp/status`, `/api/cloud-providers/status`, `/api/coordinator/context`, `/api/capability-router/status` | status views |
| POST, GET | `/upload`, `/upload/{file_id}` | file upload for ingest and chat |
| GET | `/api/docs/runbooks`, `/api/docs/runbooks/{name}` | the runbooks the gateway serves to the dashboard |

## Add-on proxy (`src/addon_proxy.rs`)

An HTTP add-on's own routes are not listed here: the add-on ships its route
manifest, the gateway mounts it at startup when the add-on is on, and the
add-on documents them. When the add-on is on but its manifest is missing or
invalid, none of its routes are mounted and `/health` reports
`addons.<name>: "unhealthy"` (the reason is in the gateway log and in every
internal call's answer). Mounted routes are forwarded to the add-on's
container at `NOO_EVOLVE_URL` over HTTPS with the gateway's client
certificate (the door is mTLS); `503` with an explanation when
`addons.evolve` is off, `503` with `state: "unreachable"` and a `reason`
(`tls`, `connect`, `dns`, `timeout`, `other`) when the container cannot be
reached — `tls` usually means the gateway and the evolve image come from different releases — and
`503` with `state: "misconfigured"` when `NOO_EVOLVE_URL` is not `https://`.

## Tasks (`routes/tasks.rs`)

A task is an objective the agent loops on until it is done.
It runs as the person who created it, on the harness of the node holding
its model or on the controller, and posts notes and its result to its own
agent-message thread.

| Method | Path | Notes |
|---|---|---|
| POST | `/api/tasks` | `{objective, model?, loop_budget?, token_budget?}` — creates and starts a task for the caller (`noo tasks create`). `token_budget` caps the prompt + completion tokens its loops may spend; leave it out for no cap of its own. `Idempotency-Key` header: a retry within 24 h returns the same task with `idempotent_replay: true`. Optional `context`. Every task carries `created_via` (`addon:<name>` when an add-on created it through a delegated token, else null); that token sees only its own add-on's tasks for the person |
| GET | `/api/tasks` | the caller's tasks; operators see everyone's, or one person's with `user=`; `state=`, `limit=` |
| GET | `/api/tasks/{id}` | state, loops, last note, result, `token_budget`, `tokens_spent`, `remaining` (null = no cap), `budget_state` (`exhausted`, `awaiting_clarification` or null), the owner's `allowance` when one is set, and its children (sub-tasks a loop delegated with `noo_task_delegate`, or the roles a collaboration fanned out) |
| POST | `/api/tasks/{id}/stop` | stopped at the next checkpoint; the loops' tool calls stand |
| POST | `/api/tasks/stop` | `{via, user?}` — stops the caller's unfinished tasks created via `addon:<name>` (revoking an add-on's background work); `user` is operator-only and not allowed with an add-on's delegated token, which may name only its own `addon:<name>` (`noo tasks stop --via`) |
| POST | `/api/tasks/{id}/context` | `{text, revision}` — context pushed into a task (`revision` >= 1, text at most 32 KiB), applied at the next loop. `200 {accepted: true, applies: "next_loop"}`; a retry of the same revision `200 {accepted: false, current_revision}`; `409` for a lower revision or a finished task; `413` when too large |
| GET | `/api/tasks/{id}/events` | `after=<seq>`, `limit=` — `{events, earliest_seq, last_seq}` |
| POST | `/api/tasks/{id}/resubmit` | `{token_budget?}` — owner only. A task parked `exhausted` gets the new budget and resumes from its checkpoint (`resumed: true`); `409` when it would still be out of tokens (the reason says whether the task or the allowance is spent). On a running task it only changes the cap (`resumed: false`) (`noo tasks resubmit`) |
| POST | `/api/tasks/{id}/ask` | `{question}` — owner only: records a question and posts it to the task's thread. The task parks `awaiting_clarification` at its next loop boundary. A loop asks with the `noo_task_ask` tool; a runner on a node with the `task_ask` rail op |
| POST | `/api/tasks/{id}/answer` | `{text}` — owner only, for a task parked `awaiting_clarification`: posts the answer to the thread and starts a new loop whose prompt carries the question and the answer (`noo tasks answer`) |

A task's **token budget** is checked between loops, never during one: a loop
that crosses it finishes, and the task then parks (`checkpointed`, not
failed) with the reason in its last note and its thread. See
[Token budgets](../operating/token-budgets.md).

A client with no loop of its own (a CLI harness, your own MCP client) reaches tasks through the user MCP door's task tools: see [MCP doors](#mcp-doors).

## Harness rail (`routes/harness.rs`)

| Method | Path | Notes |
|---|---|---|
| POST | `/api/harness/call` | one operation for the loop the caller's token was minted for (`{"op": "rag", "prompt": "…"}` …; `task_checkpoint` renews the token between a task's loops). Accepts only a node-harness token: a user JWT the gateway minted for one conversation, `harness = "node:<id>"`; such a token can reach nothing else. The conversation and the person come from the token, never the body. |

## MCP doors

| Listener | Path | Auth | Purpose |
|---|---|---|---|
| `:8080` | `POST /mcp/operator` | an `mcp:operator` service key bound to an account that holds the admin role (re-checked on every call) — mandatory, and the only credential (the shared `NOO_MCP_TOKEN` was retired on 2026-09-30; the plain-HTTP `/mcp` listener on 3100 was removed in stack-v0.2.41) | the operator door: the full tool manifest (`gateway-rust/mcp-tools-local.json`, 124 tools, plus any add-on fragment named by `NOO_MCP_EXTRA_MANIFEST`), for a machine acting as the operator |
| `:8080` | `POST /mcp/user` | a key that names a user (`POST /api/security/service-keys/self` mints your own; `noo mcp external-setup` prints the recipe); the call runs under that user's own JWT | the external door, opened by `NOO_MCP_EXTERNAL_ENABLED` (off: `404`); serves the curated user manifest (`gateway-rust/mcp-tools.json`, 33 tools) plus the seven task tools (below). The key needs the `mcp` scope and must be bound to a user (`403` otherwise) |

Both speak streamable-HTTP JSON-RPC (`POST` only: `GET` and `DELETE` are
`405`; a request body over 256 KiB is refused). Identity is re-resolved from
the key on every call, so a revoked or narrowed key stops at once. They do
**not** serve the same registry: the user door (`/mcp/user`) embeds
`gateway-rust/mcp-tools.json` (33 tools), and the operator door
(`/mcp/operator`) embeds `gateway-rust/mcp-tools-local.json` (123 tools) — a strict superset that
also includes every tool in the user manifest. Both files are generated
from `src/noomesh/mcp/tool_defs/` by `scripts/build-mcp-manifest.py` and
embedded at compile time. Set-up:
[channels/mcp-your-client.md](../channels/mcp-your-client.md).

The user door also lists seven **task tools** that are not manifest entries:
they run in the gateway (`gateway-rust/src/mcp_user_tasks.rs`) rather than
as a self-call, because the task they act on is named by id, and the door
checks that it belongs to the key's account. Every account the door admits
(User and above) gets them, and an Admin is still limited to their own tasks
(operator reach is the operator door's). Any other task, existing or not,
answers `task not found`. Each call writes the door's usual `mcp_tool_call`
audit row.

| Tool | Arguments | Does |
|---|---|---|
| `noo_task_delegate` | `objective` (required), `parent_task_id?`, `role?`, `model?`, `loop_budget?` (1–500), `token_budget?` | opens a task for the caller and starts it. With `parent_task_id` (one of the caller's live tasks) it is a sub-task on the parent's thread, capped like the in-loop tool (2 deep, 8 per parent). Without, a top-level task on a new thread. Leaving out `loop_budget` gives the default of the node it lands on, or the cluster's. Returns `task_id`, `thread_id`, `parent_id`, `node`, `dispatched`, `why` |
| `noo_task_status` | `task_id?` | the task with its children (`state`, `loops`, `last_note`, `result`, `error`, `token_budget`, `tokens_spent`, `remaining`, `budget_state`, `all_settled`); with no id, the caller's 20 most recent top-level tasks |
| `noo_task_wait` | `task_id` (required), `seconds?` (1–25, default 25) | returns when the task settles, when one of its children settles, or at the deadline with the task as it stands (`state: running`, `timed_out: true`): call again. Never holds the request past 25 s (`ops::MAX_WAIT_SECS`) |
| `noo_task_done` | `task_id`, `result` (required), `failed?` | records the result as the in-loop `noo_task_done` does and posts it to the task's thread. Done from the door does not require prior tool calls: the in-loop check that refuses a success claim from a task whose conversation called no tool is skipped, and the result is not prefixed, because a door caller's tool use happens outside that conversation |
| `noo_task_ask` | `task_id`, `question` (required) | records the question and posts it to the task's thread; the task parks `awaiting_clarification` at its next loop boundary (the running loop is not interrupted). The same tool a task's own loop has |
| `noo_task_resubmit` | `task_id` (required), `token_budget?` | as `POST /api/tasks/{id}/resubmit`: a task parked `exhausted` resumes with the new budget; a running one only gets the new cap. Returns the task with `resumed` |
| `noo_task_answer` | `task_id`, `text` (required) | as `POST /api/tasks/{id}/answer`: answers the question of a task parked `awaiting_clarification` and starts a new loop with the question and the answer |

### Add-on token exchange (`routes/addon_token.rs`)

| Method | Path | Notes |
|---|---|---|
| POST | `/api/addon/token` | trades a long-lived add-on service key (bearer carrying the `addon` scope) for a short-lived JWT scoped to that key's scopes minus `addon` — so the minted token cannot re-exchange itself. `403` if the key carries no other scope; `503` with no `NOO_JWT_SECRET`. Response: `{"token", "expires_in", "consumer", "scopes"}`. |

## Kiosk (`routes/kiosk.rs`)

A read-only projection surface for one unattended display (e.g. a
corridor screen): each handler re-shapes a general route's own output
(never a second query), dropping fields the display doesn't draw.

| Method | Path | Notes |
|---|---|---|
| POST | `/api/kiosk/token/tailnet` | the ONLY kiosk mint: no durable secret on the display — the tailnet is the credential (whois tag check + dialback nonce proof, verified by the controller's self-agent). Kill switch `NOO_KIOSK_TAILNET_MINT=0`. Returns `{"token", "expires_in": 900, "consumer"}`; `503` with no usable `NOO_JWT_SECRET`. The key lane (`POST /api/kiosk/token`, a `kiosk`-scoped service key) was retired on 2026-09-30: not routed, the scope is not issuable, and a key still carrying it is refused on every route. |
| GET | `/api/events/stream` | Server-Sent Events state stream for the display |
| GET | `/api/kiosk/nodes`, `/gpus`, `/jobs`, `/scheduler`, `/heartbeat`, `/memory`, `/rag`, `/graph`, `/addons` | projections of `cluster::cluster_status` and the equivalent general routes, trimmed to what the display renders |
| GET | `/api/kiosk/graph` | the entity-level graph: `nodes` (`id`, `type`, `degree`), `edges` (`src`, `dst`), `edges_drawn`, `edges_total`, `stats`, `reason`, `entity_count`, and **`labels: true\|false`**. Entity `name` and edge `rel_type` are included only while the controller setting `kiosk.graph_labels` is on (`noo kiosk labels on\|off`; default off; see [config.md](config.md#behavioural-flags)). The request takes no parameters — the old `?labels=1` is gone and anything in the query string is ignored — so nothing a kiosk credential sends can widen its read |

## Dashboard

`GET /` (alias `/dashboard`) serves the web UI, `/kiosk` (alias `/kiosk.html`) the kiosk page. `/assets/*` (versioned mesh-UI artifact assets) is public; `/static/*`
is **not** — only the exact path `/static/openapi.public.json` is public
there, everything else under `/static/` requires the same credential as
any other route. Every action the UI takes is one of the authenticated
calls above.
