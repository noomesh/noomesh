# Configuration Reference

`noomesh.yaml` is the configuration file for everything that is not a
secret, not a security gate, and not needed before the stack can start.
The Rust gateway, the Python workers and the `noo` CLI all read the same
file. This page lists every section, then explains where a value belongs
when it is *not* a YAML key — secrets, posture
gates, bootstrap flags and compose interpolation.

See what your install is running with:

```bash
noo config show                 # the local file, resolved from --config / $NOO_CONFIG / search path
noo config get [section]        # what the gateway has loaded, as JSON
noo config export-effective     # effective runtime config (autonomy + KB rules/grants) as YAML
```

## Where the file is found

| Reader | Search order |
|---|---|
| Rust gateway (`gateway-rust/src/config.rs`) | `/app/noomesh.yaml` (the compose mount), then `noomesh.yaml` in the working directory; `NOO_CONFIG_PATH` overrides for the write path used by `noo config set` |
| `noo` CLI (`noo-cli/src/commands/config.rs`) | `--config <path>` → `$NOO_CONFIG` → `./noomesh.yaml` → `~/.config/mesh/config.yaml`; a missing explicit path is an error |
| Python workers (`src/noomesh/config.py`) | explicit path → `$NOO_CONFIG` → `./noomesh.yaml` → `~/.config/mesh/config.yaml` |
| launcher (`scripts/lib-config.sh`) | `$NOO_CONFIG_FILE` → `./noomesh.yaml` → `$HOME/.config/noo/noomesh.yaml` |

**The launcher's search path is not the same as the CLI's or the Python
workers'.** It uses a different environment variable (`NOO_CONFIG_FILE`,
not `NOO_CONFIG`) and a different fallback directory
(`~/.config/noo/noomesh.yaml`, not `~/.config/mesh/config.yaml`). In
practice both usually resolve to the same `./noomesh.yaml` in the working
directory, but an install relying on either fallback location, or on the
env var to point somewhere else, will see the launcher and the CLI/workers
read two different files. Do not assume they are interchangeable.

Every section has defaults; a missing key never breaks startup. If no file
is found the gateway logs `No noomesh.yaml found, using defaults`.

## Precedence

For any setting that exists both as an environment variable and as a YAML
key, the gateway resolves it with `config::env_or_yaml` (and the Python
side with the same rule):

1. the environment variable, if set and non-empty — the **override**
   (set in `.env`, by compose, or by the DB security posture at boot)
2. the YAML key — the documented **default** for this install
3. the compiled-in default

A handful of settings have one more layer in front: a row in the
`noo_settings` table (behavioural flags and `NOO_HEARTBEAT_TZ`), which the
gateway re-reads every 15 s. See [Behavioural flags](#behavioural-flags).

Security invariants — gateway auth and strict cluster-token verification —
are not configurable at all: always on, fail-closed.

## Change a value

```bash
noo config set services '{"loki_url": "https://loki:3100"}'
```

`noo config set <section> <json>` deep-merges the object into that section
of the gateway's `noomesh.yaml` and rewrites the file (`PUT
/api/config/{section}`, write scope). Values that readers capture at
process start — everything resolved through `env_or_yaml`, the watched
folders, the systems manifest — take effect after
`noo stack restart gateway`; the dashboard shows a restart banner when a
change needs one.

Do not put a security gate here: `noo config set` needs only write scope,
so a gate in the YAML could be flipped by the accounts it constrains. Gates
are posture (below).

### The gateway has to be able to write the file

`noomesh.yaml` is bind-mounted into the gateway, which runs as **uid 65532**.
The file is created by the operator, so it starts out `0644` owned by their
uid and the gateway cannot write it. `noomesh-start.sh` fixes that on every
start — group `65532`, mode `0660`, applied through a throwaway root container
because a host `chgrp` needs gid-65532 membership the operator usually lacks.
The operator keeps ownership and their own write access.

If it could not (the launcher says so, and `noo config set` answers a 500 that
names the command), run:

```bash
docker run --rm -v "$PWD/noomesh.yaml":/f alpine sh -c 'chgrp 65532 /f && chmod 660 /f'
```

**The write is not crash-atomic on a dist install, and this is deliberate.**
The gateway prefers a temp file plus `rename`, but `rename(2)` onto a *file*
bind-mount returns `EBUSY` regardless of permissions — so when `noomesh.yaml`
is mounted as a file, the gateway rewrites the inode in place instead and logs
once that it did. Concurrent writers are still serialized: the lock is an
`flock` on the **directory** holding `noomesh.yaml`, which needs only read and
execute permission, has a stable inode across any rename, and exists before the
config file does. (A lock on the config *file* would be wrong here — the write
path can replace that file, leaving the winner holding a lock on an orphaned
inode.) Only a crash *during* a write could truncate the file. To get atomicity
back, mount the directory that contains `noomesh.yaml` rather than the file.

## Sections

Types and defaults are what the Rust loader (`gateway-rust/src/config.rs`)
and the Python models (`src/noomesh/config.py`) declare; the *Read by*
column says which side actually consumes the key.

### `services` — endpoints (gateway + workers)

Topology only — credentials stay in the secret store. Each key's env
override is listed.

| Key | Env override | Default | Purpose |
|---|---|---|---|
| `database_url` | `DATABASE_URL` | `postgresql://noo:noo@postgres:5432/noomesh` | gateway Postgres DSN (compose injects the `noo_app` credential); `sslmode=verify-ca` is appended automatically when `NOO_TLS_CA` exists |
| `nats_url` | `NATS_URL` | `tls://nats:4222` | NATS server; the bus serves mTLS only (`state.rs`, `preflight.rs`) |
| `redis_url` | `REDIS_URL` | `rediss://redis:6379` | Redis (optional: without it, rate limiting and caching are disabled) |
| `ollama_url` | `OLLAMA_URL` | `https://stunnel-ollama:11434` | static Ollama fallback when no mesh backend answers; ollama has no TLS of its own, so its door is the stunnel sidecar (the old `http://localhost:11434` default was dead inside the container) |
| `gateway_url` | `NOO_GATEWAY_URL` | `https://localhost:8080` | the gateway's own advertised URL (agent cards, MCP proxies, bootstrap) |
| `prometheus_url` | `NOO_PROMETHEUS_URL` | `https://prometheus:9090` | metrics source for autonomy evaluators |
| `alertmanager_url` | `NOO_ALERTMANAGER_URL` | `https://alertmanager:9093` | Alertmanager for `noo_alerts_list` (read-only; same mTLS identity as Prometheus) |
| `loki_url` | `NOO_LOKI_URL` | `""` | the env wins; compose sets it to `https://loki:3100`, so this is the fallback for a gateway run outside compose. Empty in both = `noo logs status` "not configured" |
| `nvidia_exporter_url` | `NVIDIA_EXPORTER_URL` | `https://nvidia-exporter:9400/metrics` | GPU metrics |
| `embedding_url` | `PAGEINDEX_EMBEDDING_URL` | `""` → `https://stunnel-ollama:11434` (ollama-first; the stunnel-fronted door) | the one embedder every embed call uses |
| `embedding_backend` | `PAGEINDEX_EMBEDDING_BACKEND` | `ollama` | the wire format: `ollama` (`/api/embed`), `openai` (`/v1/embeddings`), `tei` (`/embed`, legacy — TEI is no longer deployed) |
| `embedding_model` | `PAGEINDEX_EMBEDDING_MODEL` | `""` | sent in the body for `ollama` / `openai`; `tei` pins its model server-side |
| `embedding_dim` | `EMBEDDING_DIM` | `0` | expected vector width. `0` means **unknown**, and the dimension-mismatch check is skipped entirely — leaving this key out of the YAML (or setting it to `0`) turns that check off. Set it to the real width to have preflight refuse embed writes that don't match the store's `vector(N)` columns |
| `embedding_extra_urls` | `PAGEINDEX_EMBEDDING_EXTRA_URLS` | `""` | comma-separated extra static embed endpoints, same model and format as `embedding_url`. The gateway spreads embeds (least in-flight, round-robin ties) over every healthy mesh node **and** every static endpoint; a target that fails is skipped for 30 s. Used to declare the optional CPU embedder |
| `stt_url`, `stt_backend`, `stt_model`, `stt_api_key_env` | `NOO_STT_URL`, `NOO_STT_BACKEND` (`openai` \| `whisper`), `NOO_STT_MODEL`, `NOO_STT_API_KEY_ENV` | — | speech-to-text provider (the voice add-on's `whisper` service by default) |
| `tts_url`, `tts_backend`, `tts_voice`, `tts_api_key_env` | `NOO_TTS_URL`, `NOO_TTS_BACKEND` (`openai` \| `piper`), `NOO_TTS_VOICE`, `NOO_TTS_API_KEY_ENV` | — | text-to-speech provider |

There is no mesh routing for embeddings (unlike rerank): `noo onboard`
writes the values that match the deployed profile.

### `worker` — Python worker limits

| Key | Env | Default | Purpose |
|---|---|---|---|
| `global_concurrency` | `NOO_WORKER_GLOBAL_CONCURRENCY` | `32` | total in-flight handler cap (Python) |
| `timeout_secs` | `NOO_WORKER_TIMEOUT_SECS` | `120` | NATS request timeout, both sides |
| `rss_limit_mb` | `NOO_WORKER_RSS_LIMIT_MB` | `0` | restart ceiling; `0` = disabled |

### `inference` — token budget (gateway agent loop)

| Key | Env | Default | Purpose |
|---|---|---|---|
| `vllm_max_model_len` | `VLLM_MAX_MODEL_LEN` | `16384` | context window the loop budgets against |
| `vllm_max_tokens` | `VLLM_MAX_TOKENS` | `4096` | output reserve; keep ≥ 256 for thinking models |

### `coordinator` — the agent loop (gateway)

| Key | Default | Purpose |
|---|---|---|
| `enabled` | `true` | |
| `system_prompt` | `"You are Mesh, a helpful AI assistant …"` | |
| `max_iterations` | `10` | tool-call rounds per turn |
| `max_session_messages` | `20` | |
| `max_context_tokens` | unset (12288 = 16K minus the 4K reserve) | input budget |

### `heartbeat` — cron scheduler (gateway)

| Key | Env | Default | Purpose |
|---|---|---|---|
| `tz` | `NOO_HEARTBEAT_TZ` | `America/New_York` | IANA zone for cron evaluation; a `noo_settings` row wins over both and is hot-reloaded (`POST /api/heartbeat/reload` forces it) |
| `gateway_url` | `NOO_HEARTBEAT_GATEWAY_URL` | — | retired, not read: heartbeat actions call the gateway in process (no loopback) |

### `search` — what `web_search` asks (gateway)

Changes apply to the next search without a restart: `noo config set search '{"provider":"tavily"}'` takes effect immediately. An env value (`NOO_SEARCH_PROVIDER`, `NOO_SEARCH_SEARXNG_URL`) still overrides the file.

| Key | Env | Default | Purpose |
|---|---|---|---|
| `provider` | `NOO_SEARCH_PROVIDER` | key-implied | `ddg`, `searxng`, `brave` or `tavily`; unset = `tavily` if TAVILY_API_KEY is stored, else `brave` if BRAVE_SEARCH_API_KEY is, else `ddg` |
| `searxng_url` | `NOO_SEARCH_SEARXNG_URL` | — | base URL of a SearXNG instance, e.g. `http://noo-searxng:8080` |

`ddg` scrapes the public DuckDuckGo HTML endpoint. It needs no credential and
is the default so nothing has to be configured, but it is best-effort: the
endpoint rate-limits and soft-blocks, answering a challenge page instead of
results. When that happens the tool now **fails** rather than reporting an
empty result set, so a model cannot write a report from nothing.

For search that reliably runs, pick another provider:

- **`searxng`** — an instance you host. No third-party key, which suits a
  self-hosted cluster. Enable `json` in the instance's `search.formats`; it is
  off by default, and without it the API answers HTML and the provider errors
  saying so.
- **`brave`** / **`tavily`** — set `BRAVE_SEARCH_API_KEY` or `TAVILY_API_KEY` in the secret store (`noo security secrets rotate TAVILY_API_KEY --set-from-stdin --yes`); the wizard asks for a Tavily key beside the cloud keys and sets the provider when one is given. DuckDuckGo needs no key and rate-limits scrapers at its own discretion, so a report can fail on it without anything being wrong on your side.
  A key is a secret, so it belongs in the secret store and is read from the
  environment; it must never be written into `noomesh.yaml`.

### `mcp` — the MCP doors and external servers

| Key | Env | Default | Purpose |
|---|---|---|---|
| `enabled` | — | — | **retired/unread**: `McpConfig` (`gateway-rust/src/config.rs`) has no `enabled` field at all — nothing parses or reads this key. The doors are controlled elsewhere: the operator door (`/mcp/operator`) is always on, and the user door (`/mcp/user`) is gated by the posture key `NOO_MCP_EXTERNAL_ENABLED` (see [posture gates](#where-does-a-value-go)), not by anything in this section |
| `port` | `NOO_MCP_PORT` | — | **retired** (stack-v0.2.40): the separate listener it bound is gone; the key is tolerated and unread |
| `timeout` | `NOO_MCP_TIMEOUT` | `120` | tool-call timeout (s) |
| `tools_filter` | `NOO_MCP_TOOLS` | `all` | comma list of tool names, or `all` |

### `cluster` — backends and placement (gateway + workers)

| Key | Default | Purpose |
|---|---|---|
| `default_backend` | `vllm` | |
| `backends.<name>.enabled`, `.model` | — | per-backend defaults (`ollama`, `vllm`, `llamacpp`); vLLM also takes `quantization`, `gpu_memory_utilization`, `extra_args` (`tool_call_parser`, `tensor_parallel_size`) |
| `shard_key` | env `NOO_SHARD_KEY` → `NODE_ID` → `default` | tag written into every conversation's metadata |
| `auto_scale`, `idle_timeout_sec`, `pinned_backends[]` | `true`, `1800`, `[]` | placement policy (Python) |

### `security` — exec approval

> **`exec_approval_mode` is not a config key.** It is a posture gate
> (`NOO_EXEC_APPROVAL_MODE`) and only a posture gate. Setting it here is a
> **startup refusal** in both runtimes — the gateway exits 2
> (`posture::yaml_gate_refusal`) and `SecurityConfig` raises — rather than
> being silently ignored. Set it with
> `noo security posture set NOO_EXEC_APPROVAL_MODE approval`, then restart the
> gateway. Unset everywhere = `strict`. Why it moved: this file is writable
> over `PUT /api/config/security`, which the agent's own `noo_config_set` tool
> reaches, so the gate deciding whether the model may run HIGH-risk tools was
> writable by the model.

`PUT /api/config/security` — like `tls`, `tools`, `workspace` and
`watched_folders` — now requires an **Admin JWT** and refuses any
cluster-token caller: each of those sections feeds a security decision
(`FilePolicy`'s allowed and writable roots, the risk classifier's tool lists,
the TLS material). `noo_config_set` of any of the five is classified HIGH, so
the agent's own config tool gates under approval mode as well.

| Key | Env | Default | Purpose |
|---|---|---|---|
| `exec_approval_timeout` | — | `300` | decision-window seconds, read by the **Python worker's** approval manager. The Rust gate and `GET /api/exec-approval/status` use `NOO_EXEC_APPROVAL_TIMEOUT_SECS` (also `300`, clamped to 1–3600) and ignore this key |
| `high_risk_tools`, `medium_risk_tools` | — | see `config.py` | classifier inputs for the Python worker |
| `jwt_secret`, `cluster_secret` | `NOO_JWT_SECRET`, `NOO_CLUSTER_SECRET` | — | modelled for completeness; **keep them in the secret store, not here** |

### `tls`

`cert`, `key`, `ca` — paths, modelled for completeness. The switches that
actually enable TLS are the `NOO_TLS_*` environment variables written by
`noo onboard`.

### `watched_folders` and `watched_drives` — auto-ingest (gateway)

| Key | Default | Purpose |
|---|---|---|
| `enabled` | `false` | |
| `folders[]` | `[]` | a path, or `{host, mount, label, writable}` |
| `drives[]` | `[]` | `{drive_id, folder_id, label, recursive}` (Google Drive) |
| `patterns` | `*.pdf *.md *.txt *.html *.docx *.pptx *.xlsx *.csv` | |
| `poll_interval_seconds` | `60` (folders), `300` (drives) | |
| `recursive` | `true` | |
| `max_batch_size` | `10` | |
| `max_file_size_mb` | `25` | |
| `notify_channels`, `notify_recipients` | `[]` | where ingest reports go |

### `workspace` — writable agent output dir (gateway + workers)

`enabled` (`false`), `host` (host path, informational), `mount` (container
path, default `/workspace`). Distinct from watched folders: workspace
content is ingested only on request.

### `tools` — the Python tool registry, plus `allowed_paths`

`enabled` (`[web_search, python_exec, local_files]`), `selection_mode`
(`smart` \| `all`), `max_selected`, `min_score`, `selection_scoring`
(`jaccard` \| `bm25`), `always_include`, and `allowed_paths` — the read
allow-list for the native `local_files` tool (merged with watched-folder
mounts and the workspace by the gateway).

### `memory`

`enabled`, `min_score`, `session_top_k`, `global_top_k` and the Python
`MemoryConfig` fields (`include_session`, `include_global`,
`retrieval_scoring`, `max_chars`, `pgvector.*`). The gateway reads only the
two `top_k` values.

### `kb` — knowledge-base role tagging (workers)

`source_roles[]` of `{match: <glob>, roles: [...]}` — ingests with **no
uploader identity** (watched folders, Drive, internal loops) inherit audience
roles from their provenance, first glob match wins. A signed-in person's
upload never takes a source rule: it is theirs until they share it.
`default_roles` (`[]`) is the fallback for no-uploader ingests that match no
rule; empty means admin-only. Read by
`src/noomesh/gateway/kb_roles.py`.

**Audience rules.** Every document is stored with an audience; there is no
untagged document.

1. Roles given on the ingest call (`noo rag ingest --audience
   <role>[,<role>]`, or the console's audience selector). A non-admin may
   only tag `user:<own name>`, `company` and `team:<name>` they were granted;
   `admin` and `system` are never writable by a non-admin. A request outside
   that falls back to the uploader's own tier.
2. A signed-in account, from the CLI login or the console session, admin
   or not: `user:<account>`. An upload is yours until you share it with a
   team or the org; neither a source rule nor `default_roles` widens it.
3. No uploader identity: a matching `source_roles` rule (or
   `noo_kb_source_rules` row), else `default_roles`, else the explicit tag
   `admin`.

Documents ingested before this rule, and carrying no audience, stay visible
only to admins (unchanged). Make that explicit with the backfill below.

Listing and graph obey the same audience as retrieval: `GET /api/v1/docs`,
the entity, neighbour, overview and cluster routes show a non-admin only what
`rag query` would read (their own `user:<account>`, `company`, `system` and
granted `team:*`), and the gateway asks the worker for that set rather than
keeping its own copy of the rules.

The Intelligent-tier graph routes (`navigate`, `traverse`, `explain-path`,
`semantic-search`, `search-clusters`, `recall-traversals`, `extract-relations`)
and the snapshot curriculum obey it too: the gateway hands the caller's audience
to the worker as `roles` and the Intelligent tier filters while it walks, so a path
never passes through, and a count never includes, something the caller cannot
read. A cluster with an unreadable member is shown with its readable members
only and a label built from their names, never the stored one (it was written
from all of them). `extract-relations` runs only over a page the caller can
read. Stored traversals are re-filtered on read: the path must be readable, and
a traversal's query text is shown only to the user who ran it. A user's saved
graph threads (`kind='thread'`) are not served by `recall-traversals` at all:
they come back through `GET /api/v1/walks`, which revalidates every step, edge
and evidence document against the current graph for the caller (see
[Recallable walks](#walks--recallable-walks-saved-graph-threads)). The curriculum
is built from the temporal graph, so there a concept is readable when the
caller owns, or a readable document supports, a fact it was built from.
`classify-intent` reads only the query string and stays open. The Intelligent-tier
image is not pinned by the stack tag, so a restricted caller is answered only
when the worker confirms it filtered (`audience_filtered`); an older worker or
intel gives a 503, never an unfiltered answer. `GET /rag/status`,
`/graph/stats` (counts) and the kiosk graph (structure only, unless the
operator's `kiosk.graph_labels` is on) are unscoped by design.

The snapshot routes obey it as well: for a restricted caller `POST /api/snapshots/diff` diffs only the concepts they can read, and `GET /api/snapshots` and `/{id}` show a neutral label (`<kind> snapshot <date>`), no slice spec and their own readable concept and edge counts instead of the stored label and whole-graph stats.

Both apply **at ingest only**. A document already in the store keeps the
audience it was given, so adding a rule does not reach the documents that
prompted it — leaving `default_roles` empty is therefore a decision about
every document ingested from an unmatched source until someone notices.
`noo rag retag` is how an audience changes afterwards, for a backfill or a
relabel:

```sh
noo rag retag --match 'gdrive://*' --role team:founders          # dry run
noo rag retag --match 'gdrive://*' --role team:founders --apply
noo rag retag --match 'gdrive://*' --role team:research --relabel --apply
```

Backfill for documents that predate the audience rule (untagged → `admin`,
which is what their visibility already was). `--match` is a glob on
`source_uri`; a document stored with no `source_uri` needs `--doc-id`:

```sh
noo rag retag --match '*' --role admin           # dry run, untagged only
noo rag retag --match '*' --role admin --apply
```

Dry-run unless `--apply`, and untagged-only unless `--relabel`: backfilling
an unclassified document and overwriting a classification somebody chose are
separate acts. A document always has an audience, so `--role` is required
and there is no way back to untagged: `--clear` is refused (to make a
document admin-only, `--role admin`). Target roles are clamped to what the caller could write to itself, so an operator cannot
publish someone's private documents into a team they do not belong to, and
a `team:` role must exist (`noo security team create <name>`) before anyone
holds it.

**Reviewing document audiences.** After an upgrade, or whenever the corpus
has grown, an operator can go through every document, decide whether its
audience is right, and change it. The tools are `noo rag docs`, `noo rag doc`
and `noo rag retag` (and the MCP tools `noo_docs_list`, `noo_doc_detail`,
`noo_rag_retag`, operator door only).

1. **Backfill** anything untagged to `admin`, which is what its visibility
   already was (the two commands above, ending in `--apply`).
2. **List what to review.** The last line is the summary, taken over the
   filtered set: `269 documents · 0 untagged · admin 150 · user:* 80 · company 39`.

   ```sh
   noo rag docs                              # every document, paged
   noo rag docs --audience admin             # the ones the backfill made admin-only
   noo rag docs --untagged                   # should be none after step 1
   noo rag docs --audience 'user:*'          # every personal tier
   noo rag docs --match 'gdrive://*' --title budget
   ```

   `AUDIENCE` shows the real tags (`user:alice`, not `user:*`), `INGESTED` is
   the path and account that created the document (`cli/alice`, `heartbeat`,
   `drive`; `unknown` for documents from before provenance was recorded) and
   `EDITS` counts audience changes.
3. **Inspect** one: audience, provenance, every past audience change
   (`at`, `by`, `from → to`, last 20) and the first ~1000 characters.

   ```sh
   noo rag doc <id>
   ```
4. **Retag.** A dry run prints each document's `from → to`; `--apply`
   writes. Documents that already carry an audience (all of them, after the
   backfill) need `--relabel`.

   ```sh
   noo rag retag --doc-id <id> --role user:alice --relabel
   noo rag retag --doc-id <id> --role user:alice,team:ops --relabel --apply
   noo rag retag --match 'gdrive://*' --role company --relabel --apply
   ```
5. **Verify** with the summary line (`noo rag docs --audience admin` should
   shrink by what you moved) and `noo rag doc <id>`, whose history now ends
   with your change.

Each applied retag is traceable twice: on the document (`audience_history`,
the last 20 changes) and in the security audit log (`kb_retag`: who, the
selector, the target roles, the document ids; `GET /api/security/audit-history`). A
refused apply is logged too. `provenance` is written once, by the ingest
that creates the document, and a re-ingest of the same content never
overwrites it. `via` is a coarse label read from the request: `cli`
(a `file://` source), `upload` (console upload), `mcp` (the MCP door; user
and operator doors are not told apart), `api` (any other signed-in call),
`folder` / `drive` (the ingest loop), `heartbeat`, `research`, `internal`.

### `walks` — recallable walks: saved graph threads

A signed-in account's `navigate`, `traverse` and `rag` walks are saved after
the reply as `kind='thread'` rows (`workers/walks.py`) and come back through
`GET /api/v1/walks`, `noo walks` and the `noo_walks_recall` tool: only the
caller's **own**, verbatim, **re-checked against the current graph for their
audience** (an unreadable step, a removed edge, a deleted document, a
superseded fact or a rejected verification drops a walk; nothing stale is
served). Internal and heartbeat walks are not threads.

**Saving is a per-account switch, on by default**: `noo walks settings --save
off` (or `PUT /api/v1/walks/settings {"save_threads": false}`) stops NEW saves
and deletes nothing. It is stored per account in `noo_user_settings` under
`walks.save_threads` and is erased with the account. A setting the worker
cannot read is treated as OFF.

Who may read what: an account its own threads; an operator **counts only**
(`GET /api/v1/walks/stats`, `noo walks stats`); an admin a user's threads
through `GET /api/v1/admin/walks?user=` (`noo walks view`), which writes one
`noo_security_audit` row (`walks_admin_view`) per view.

Install-wide tuning (`noomesh.yaml`, `walks:`; read by the worker at start):

| key | default | |
|---|---|---|
| `soft_gating` | `false` | Filter recall on the soft gates below. **Off = log first**: every candidate's `walk_recall_verdict` line carries `U` and each gate, and nothing is filtered on them. Turn on after reading the distribution. |
| `min_relevance` | `0.55` | soft gate: minimum query similarity |
| `min_usefulness` | `0.5` | soft gate: minimum `U` |
| `min_confidence` | `0.5` | soft gate: minimum current edge confidence on any step |
| `freshness_half_life_days` | `90` | half-life of the freshness term |
| `thread_ttl_days` | `180` | a thread expires this long after it is saved |
| `max_threads_per_user` | `500` | over it, the least-recalled (then oldest) active threads are **staged** out of recall, not skipped |

`U = 0.35·accuracy + 0.25·freshness + 0.40·relevance`: accuracy from the walk's
edges' current confidence (weakest link) and, for a rag walk, its verification;
freshness `0.5^(age/half-life)` of the newest evidence; relevance the query
similarity. The **hard** gates always apply regardless of `soft_gating`.

### `edge` and `companion` — removed

These sections were read by nothing. Companion gating is
**per-node desired state**, not configuration: `noo cluster set-config
<node> --min-battery <pct> --require-wifi <bool> --block-thermal <s,s>`,
`--policy-default` to clear, or `companion_policy:` under a node in the seed
file. The agent loop's placement policy is the same kind of thing:
`harness_policy: auto|manual|off` under a node, or
`noo cluster provision <node> --harness …` / `set-config --harness …`. `noo cluster desired <node>` shows what applies.

### `systems` — the per-system database manifest (gateway broker)

Declares which systems extend the database and who owns what. The gateway
reads it on every boot and provisions each declared system: its schema, a
DDL role that owns the schema, and a runtime role that reads and writes
without `CREATE`. Passwords come from the named env vars (generated by
`noo onboard`). Without this section nothing is provisioned and preflight
fails closed on a fresh install.

```yaml
systems:
  trellion:
    role: noo_trellion
    ddl_role: noo_trellion_ddl
    schema: trellion
    password_env: NOO_TRELLION_DB_PASSWORD
    ddl_password_env: NOO_TRELLION_DDL_PASSWORD
    extensions: [vector, pg_trgm]     # installed by the broker (need superuser)
  example_addon:
    role: noo_example_addon
    ddl_role: noo_example_addon_ddl
    schema: example_addon
    password_env: NOO_EXAMPLE_ADDON_DB_PASSWORD
    ddl_password_env: NOO_EXAMPLE_ADDON_DDL_PASSWORD
    # no enabled_when: a system named after an add-on follows the
    # `addons:` map. Only a system that is NOT an add-on names an env flag.
```

`enabled_when` names the env flag that decides whether the system is
provisioned; it is deliberately not "is the password set", because the CLI
generates every role password unconditionally.

### Other sections

| Section | Read by | Keys |
|---|---|---|
| `ollama`, `agent`, `context`, `web_search`, `sandbox` | Python reference CLI / tools | `base_url`, `model`, `options`; `system_prompt`, `max_tool_loops`, `tool_mode`; `files`; `provider`, `max_results`; `url` (`NOO_SANDBOX_URL`) |
| `cache` | workers | `enabled`, `ttl` |
| `video_memory` / `recall_memory` (recall memory). Keep `video_memory:` until the evolve add-on's update ships; `recall_memory:` is accepted. The old key warns once at boot, loses to `recall_memory` when both are set, and is removed in the release after 0.6.0. `GET /api/config` also shows a `recall_memory` section under `video_memory` (read-only alias) until then | workers (recall) | `enabled` |
| `terminal` | workers | `default_backend`, `default_model`, `context_length`, `auto_create_variants` |
| `self_identity` | workers | `focus` |
| `ocr` | workers | `enabled`, `model`, `min_text_length`, `dpi`, `prompt` |

### `compose_env` — values compose interpolates

Compose substitutes `${VAR}` from the process environment or `.env` and
from nothing else; it cannot read this file. `scripts/lib-config.sh`
(`load_config`, run by every launcher) exports this flat section before
compose runs. That is what lets deployment values live here instead of in
`.env`:

```yaml
compose_env:
  NODE_ID: noo-controller
  NODE_IP: 100.64.0.1
  NODE_TIER: 1
  CLUSTER_MODE: controller
  VLLM_MODEL: google/gemma-4-12B-it-qat-w4a16-ct
```

An already-set environment variable always wins (`NODE_ID=other noo stack
start` still overrides). A key present in **both** `.env` and
`compose_env` is reported loudly at every launch — two sources with a
silent winner is the failure this split exists to remove.

## Where does a value go

Three planes, one home each. A value in two of them creates a silent
winner.

| Plane | Home | Holds | Applied by |
|---|---|---|---|
| **Secrets** | `secrets/env.sops` (`NOO_SECRETS_BACKEND=sops`) | passwords, API keys, tokens, passphrases | `scripts/lib-secrets.sh` (`load_secrets`) before compose; `noo security secrets …` to edit |
| **Config** | `noomesh.yaml` | everything else — nested sections for the application, `compose_env` for compose | `env_or_yaml` at runtime; `load_config` before compose |
| **Posture** | `noo_security_posture` table | a short allow-list of security gates | `noo security posture …`; restart to apply |
| *(bootstrap)* | `.env` | the flags read before the secret store or the YAML can load | the launcher shell |

Decide in this order:

1. **Would leaking it hurt?** → the secret store. Never also in `.env`.
2. **Is it one of the posture gates?** → posture. The list is an allow-list
   in `gateway-rust/src/posture.rs` and `src/noomesh/posture.py`, pinned to
   each other by `tests/test_posture_key_parity.py`:

   | Gate | Meaning |
   |---|---|
   | `NOO_EXEC_APPROVAL_MODE` | `auto` \| `approval` \| `strict` tool-execution gating |
   | `NOO_NODE_AGENT_PRIVILEGED` | whether the node-agent **container** runs privileged — an opt-in compose profile the fleet does not deploy; every node runs the host binary as `noo-agent` in the `docker` group ([node-agent.md](../security/node-agent.md)) |
   | `NOO_MCP_EXTERNAL_ENABLED` | opens the user MCP door (`/mcp/user`) |
   | `NOO_SELF_CALL_SHARED_SECRET` | a *bridge*, not a gate: closed by default (unset = closed); only `1` / `open` holds it open. While open, a shared-secret token still buys inference and every acceptance warns naming the caller; closed, callers must present their own `noo_service_keys` row. It does not retire `NOO_CONTROLLER_SECRET`, whose one remaining job is the gateway's boot guard |

   At boot the gateway (and the Python worker) read the table and set those
   keys in the process environment *before serving*, so the DB is
   authoritative and `.env` is only the bootstrap fallback.
   `POST /api/security/posture` is operator-only: an app-admin JWT is
   refused; the cluster credential is required.

   ```bash
   noo security posture list                 # running vs desired, pending_restart
   noo security posture set NOO_EXEC_APPROVAL_MODE approval
   noo security posture apply-profile hardened   # or: dev
   noo stack restart gateway
   ```

   Profiles: `hardened` = `approval` mode, unprivileged node-agent container;
   `dev` = `auto` mode, privileged node-agent container. Neither changes what
   a node accepts from the controller — that is the node's own contract, not
   a posture key ([node-agent.md](../security/node-agent.md)).
   Tenant isolation is deliberately not a
   gate here: an unattributed data read resolves a scope (the sole account on
   a single-account install) or fails closed, on every install.
   Both leave the external MCP door **closed** — opening it is a decision
   about a specific person, made with a single-key `posture set`.
3. **Must it exist before the DB or the secret store can be read?** →
   `.env`. That is `NOO_SECRETS_BACKEND`, `NOO_INSTALL_MODE` (dev vs dist),
   `NOO_IMAGE_TAG`, the data-root trio (`NOO_DATA_ROOT` / `NOO_INSTANCE` /
   `NOO_PORT_OFFSET`) and `NOO_DEFAULT_PROFILE` — read by the launcher
   scripts straight from `.env` before compose files are even chosen.

   **The four add-on flags used to be on this list and are gone.** Which
   add-ons run is declared in `noomesh.yaml` under `addons:`; the launcher
   reads that map to compose each enabled add-on's overlay file and the gateway reads the same
   mounted file for routing and refusals. `noo stack start` refuses to run
   if it still finds `NOO_PRO_ENABLED`, `NOO_TRELLION_ENABLED`,
   `NOO_TRELLION_INTEL_ENABLED` or `NOO_VOICE_ENABLED` in `.env` — a stale
   flag beside a live declaration is how a licensed add-on silently changes
   state on upgrade. The TLS/mTLS family
   (`NOO_TLS_*`, `NOO_NATS_TLS`, `NOO_PG_SSLMODE`, `NOO_REDIS_TLS`,
   `NOO_MTLS_*`) is also env-only for good: it must not be weakenable from
   a YAML edit and is needed to *connect* to the database.
4. **Everything else** → `noomesh.yaml`: a nested section if the
   application reads it at runtime, `compose_env` if compose interpolates
   it or a host script needs it.

Two rules that follow from this:

- **If the system already declares a fact, config must not restate it.**
  The embedding model of a placement, the vector dimension of a column, a
  channel's linked identity — a restatement becomes a stale override that
  silently wins.
- **Verify against the container, not `docker compose config`** (which
  reads `.env`, not what the launcher injects), and not with
  `docker exec … printenv` (the gateway image has no shell):

  ```bash
  docker inspect noo-gateway --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^VAR='
  ```

  Env changes need a container **recreate** (`noo stack restart --force`),
  not a restart.

## Asynchronous operations

The long routes (recluster, extract-relations, consolidate, navigate, traverse,
ingest) start an operation and wait a bounded time for it before answering with
the result (`200`) or a handle (`202`); see
[api.md](api.md#asynchronous-operations-routesopsrs). Settings, all resolved
`noo_settings` row → env var → default, and so hot-reloaded within ~15 s (they
are registered string settings, so an admin sets them with
`POST /api/settings/flags/set`):

| Key | Default | Meaning |
|---|---|---|
| `NOO_OPS_WAIT_GRAPH_RECLUSTER_SECS` | `0` | seconds the route holds a request before answering `202` (`0` = always a handle) |
| `NOO_OPS_WAIT_GRAPH_EXTRACT_RELATIONS_SECS` | `3` | same |
| `NOO_OPS_WAIT_GRAPH_ENTITY_CLEANUP_SECS` | `3` | same |
| `NOO_OPS_WAIT_SNAPSHOTS_CONSOLIDATE_SECS` | `3` | same |
| `NOO_OPS_WAIT_GRAPH_NAVIGATE_SECS` | `12` | same; comfortably above a navigation's usual runtime |
| `NOO_OPS_WAIT_GRAPH_TRAVERSE_SECS` | `12` | same |
| `NOO_OPS_WAIT_RAG_INGEST_SECS` | `3` | same |
| `NOO_OPS_WAIT_DOCS_INGEST_SECS` | `3` | same |
| `NOO_OPS_RESULT_TTL_SECS` | `86400` | seconds a finished operation's result is kept (60 to 2592000) |

Every wait is capped at 25 s, whatever is set. `?wait=<s>` on a request
overrides it for that request. Read from the environment only (no admin
setting): `NOO_OPS_MAX_ACTIVE_PER_OWNER` (default 8, live ops per account) and
`NOO_GATEWAY_INSTANCE` (the runner id; default the hostname). If one gateway
instance's container is recreated its old rows are failed by the heartbeat
sweep rather than at boot.

## Behavioural flags

Feature toggles an admin may flip from the dashboard without a restart.
Resolution at every read: `noo_settings` row → env var → registered
default, cached and refreshed every 15 s. The registry
(`gateway-rust/src/routes/settings.rs`, mirrored in
`src/noomesh/settings.py`):

| Flag | Category | Default |
|---|---|---|
| `CLOUD_PROVIDERS_ENABLED` | features | off |
| `NOO_EVOLVE_HOFSTADTER_ENABLED` | features | on (with the evolve add-on) |
| `kiosk.graph_labels` | kiosk | off — **DB only** (see below) |
| `NOO_HEARTBEAT_TZ` (string) | heartbeat | `America/New_York` |
| `NOO_REPORTS_DRIVE_FOLDER_ID` (string) | heartbeat | empty (reports are sent inline) |
| `NOO_OPS_WAIT_<TYPE>_SECS`, `NOO_OPS_RESULT_TTL_SECS` (strings) | ops | see [Asynchronous operations](#asynchronous-operations) |

`CLOUD_PROVIDERS_ENABLED` gates every `claude-*`, `gpt-*` and `gemini-*`
model. With it on and the provider's key in the secret store
(`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` or
`GOOGLE_API_KEY`), such a model runs the same agent loop as a node model —
tools, memory, retrieved context, session — on the controller, calling the
provider directly. A provider that fails is reported as that provider's
error; the turn never falls back to a node model, and a failing node never
falls back to a cloud provider.

`NOO_SELF_MODIFY_ENABLED` (category `selfdev`) was also removed: the
state-changing self-admin MCP tools it gated are gone, so the model can no
longer restart or rebuild its own stack and the flag had nothing left to
switch. The `/api/mesh/restart` and `/api/mesh/rebuild` endpoints it used to
gate now require the **Admin** role instead — the gate was replaced before the
flag was deleted, since dropping a default-off flag on its own would have
opened those endpoints.

The `NOO_AGENT_*` gates and `NOO_SELF_DEVELOP_AUTO_RESTART` are not in this
registry. The add-on that owns them reads them from its own container
environment; a row here would be a switch on another process's behaviour that
this one cannot honour.

`kiosk.graph_labels` decides whether `/api/kiosk/graph` sends the kiosk
display entity names and relation types. It has **no env layer**: it is the
`noo_settings` row or the default (off), so who switched names on and when
is always on record (`updated_by`, `updated_at`, and a `setting_flag_set`
audit event). It replaces the gateway env var `NOO_KIOSK_GRAPH_LABELS`,
which is retired and ignored — there was no one-release overlap, because
the page never asked for names under the old two-party rule, so no display
was showing them. Switch it from the controller with
`noo kiosk labels on|off|status`, or from the console's admin panel. The
gateway that handles the write applies it at once; any other gateway
instance within the 15 s reload. The kiosk credential cannot write it
(refused before dispatch, and again in the handler), and nothing the
display sends can turn it on. While it is on the display shows
`LABELS ON`, `noo kiosk status` on the display says so, and
`noo cluster verify --controller` reports a WARN (`kiosk labels`: entity
names are shown on the kiosk display) — never a FAIL.

`GET /api/settings/flags` lists them with the winning source (`db` / `env`
/ `default`) and, for a `db` row, `updated_by` and `updated_at`;
`POST /api/settings/flags/set {key, value}` is Operator/Admin-only (never a
kiosk credential) and audited. Add-ons are not in this registry either: a DB toggle cannot affect
what the launcher deploys, because the launcher runs before the database
does. They live in `addons:` — see above.

## Related

- [env.md](env.md) — every environment variable each component reads
