# Fleet

Covers: node management, provisioning (bootstrap-token + pull rail) and teardown (`cluster`), the model catalog and pulls (`models`), the cluster tool registry (`tools`), running prompts on the GPU cluster (`inference`), the job queue and scheduler (`jobs`), the autonomy engine (`autonomy`), containerized skills (`skills`) and browser automation (`browser`).

Does not cover: the Docker stack on THIS host (`noo stack`), or memory and the knowledge base (`noo memory`, `noo rag`).

## Disambiguation

- `noo cluster` is the **fleet**: nodes, their desired state, enrollment and teardown. `noo stack` (Stack & data) is the Docker stack on **this host** — start, stop, rebuild, clean.
- `noo cluster place` **declares** that a node should run a backend with a model and lets the node-agent converge to it; `noo cluster down` is the older **imperative** stop call and is not remembered across an agent restart.
- `noo inference run` sends one prompt straight to a backend; `noo inference agent` runs the coordinator's full agentic loop (plan, tools, reflect); `noo jobs run` queues the prompt through the scheduler and polls the job. `noo chat` (Agents & channels) is the streaming conversation.
- `noo models` is the **catalog** (search, info, recommendations, pull through the gateway's Ollama proxy); getting a model onto a **specific node** is `noo cluster ship-model`, `sync-model-files` or a placement.
- `noo autonomy` is the self-healing engine (condition → action patrols); `noo heartbeat` (Stack & data) is the cron scheduler for user-facing tasks.
- `noo skills` runs **containerized code** in a sandbox on a node; `noo prompt-skills` (Memory & knowledge) are prompt templates; `noo tools` is the gateway's registry of the tools an agent may call.
- `noo cluster clean-node` is retired: it reported success while doing nothing on a pull-enrolled node, then de-registered it. Use `noo cluster teardown-node <node>` to dismantle, `noo cluster forget <node>` for a dead node, or `sudo noo-deenroll` on an orphaned node. `noo cluster add-node` was removed (2026-09-03) — it drove Ansible playbooks that no longer ship; enrol with a bootstrap token and finish with `noo cluster provision`. 

Retired in 0.6.12 (each still answers with its successor instead of "unknown command" for one release, and is hidden from help):

| Retired | Use instead |
|---|---|
| `noo cluster up`, `noo cluster scale` | `noo cluster place <node> <backend> <model>` and `noo cluster unplace <node> <backend>` |
| `noo cluster place-model`, `auto-place`, `reconcile-models` | `noo cluster place`, then `noo cluster prefer` or `noo cluster class set` to steer which model is tried first |
| `noo cluster mint-join-key` | `noo cluster invite` |
| `noo cluster assign` | `noo jobs run <prompt> --node <node>` |
| `noo cluster add-companion`, `add-monitor` | `noo enroll` on the device; the agent registers itself on its first heartbeat |
| `noo cluster stage-images [--lock] [-i IMG]… [--arch a,b] [--all-images]` | `noo cluster sync-images --stage-only` with the same flags (`sync-images` is now the one image verb: without `--stage-only` the named nodes then pull) |
| `noo proactive history` | `noo proactive status` (nothing records proactive firings) |

`noo cluster desired <node>` is an alias of `noo cluster show <node>`; `show` ends with the desired config and placements.

## Recipes

### Enroll a node end to end

On the controller, mint a single-use token bound to the node's name:

```sh
noo cluster bootstrap-token create --node gpu-2 --ttl 1h
```

By default this also mints a tagged Tailscale auth key and prints a
self-contained paste:

```
run AS YOUR USER on the node (one sudo prompt)
step 1 — make sure the noo CLI is on the node (skip if `noo --version` already works):
  command -v noo >/dev/null || curl -fsSL https://github.com/noomesh/noomesh/releases/latest/download/install.sh | sh
step 2 — enroll (joins the tailnet, runs host prep, installs the agent):
  noo enroll noo1.<blob>
bound to node: gpu-2. When the paste finishes: noo cluster provision gpu-2 --wait
```

The raw token is shown once and never stored; `--no-tailscale` prints the
same paste without a tailnet key, for a node already on the network; `--cidr`
restricts where it can be redeemed. `noo cluster bootstrap-token list`
shows `id | status | created by | expires | used by | role`;
`revoke <id>` is idempotent.

Paste the one-liner on the node (it ends `enrollment complete`), then back
on the controller:

```sh
noo cluster provision gpu-2 --wait
```

`--wait` (default 1800 s) polls until the node's token shows as redeemed,
settles 20 s for host prep, records the node's address and user from the
redemption record, derives the tier from the node's live facts once it has
heartbeated, else from the hardware facts it reported at enrollment (SBC or bare ARM → 4, GPU → 2, else 3; unified
memory goes by usable GPU memory — CUDA ≥ 10 GB → 1, ≥ 4 GB → 2, else 4;
pass a tier argument to override; a node with no facts on record must
re-enroll), issues the node cert, and builds **one CA-signed bundle**
(agent env with the credentials, systemd unit, agent binary, certs). On a
pull-enrolled node the bundle is encrypted to the node's birth cert and
staged at the gateway; the node's fetcher collects it and reports back:

```
staged — waiting for gpu-2 to pull, apply and report (up to 10 min; an idle node polls about every 5)
gpu-2 fetched the bundle — waiting for decrypt + apply
gpu-2 reported: applied (exit 0)
gpu-2: provisioned via pull (tier 2, amd64)
```

A node enrolled before the pull rail existed has no birth cert on record
and cannot collect a staged bundle; re-enroll it rather than reaching in.
The SSH gate lane is retired. `--local` provisions this controller's own
self-node. Then confirm:

```sh
noo cluster status
```

Columns are `node | status | bus | load | running | can-run` (`running` =
backends live now, `can-run` = backends the node is able to host); a node
off the NATS bus gets a warning line. `--watch 5` redraws on a TTY.
The tailnet-native
alternative is `noo cluster invite`, which prints
`noo enroll --via-tailnet https://<controller> --ts-authkey <key>` (needs
`tailscale serve` on :8080).

### Declare what a node should run

```sh
noo cluster place gpu-2 ollama qwen2.5:7b-instruct
noo cluster desired gpu-2
noo cluster unplace gpu-2 ollama
```

### Run it on CPU or GPU

`--on cpu|gpu` declares the hardware a placement runs on, and is stored
with it:

```sh
noo cluster place gpu-2 llamacpp gemma-3-27b-it-Q4_K_M.gguf --on cpu
noo cluster place gpu-2 ollama harrier --role embed --on cpu
noo cluster fit gpu-2 --with llamacpp gemma-3-27b-it-Q4_K_M.gguf --on cpu
```

| backend | `--on cpu` means |
|---|---|
| llamacpp | `N_GPU_LAYERS=0` in the placement env; the container gets no GPU device |
| ollama | the container gets no GPU device (`CUDA_VISIBLE_DEVICES` emptied). One ollama serves every role on a node, so it runs on CPU only when every role asks for cpu |
| vllm | refused: vLLM runs on a GPU only |

With no `--on`, a placement keeps the target it already has; otherwise
`N_GPU_LAYERS=0` means cpu, and a node with a GPU defaults to gpu. `--on
gpu` on a node that reports no GPU is refused.

`noo cluster fit` budgets each placement against its own pool: a gpu
placement against GPU memory (`vram`, or the `unified` GPU share on Apple
Silicon), a cpu placement against RAM (on a unified-memory node, the RAM
the GPU share leaves). A model is sized from, in order: what the node
reports, the GGUF in the controller model store (`MODELS_DIR`, else
`<NOO_DATA_ROOT>/models`, read by the CLI), what another node reports for
the same model, the registry, and the parameter count in its name. When
none of those answers, `fit` says **can't judge** rather than guessing.

`place` also tunes the runtime from the node's reported hardware
(`cpu_cores`, `ram_gb`, `vram_gb`) and its **usage profile**, and prints
each value with the reason:

| key | `shared` | `dedicated` |
|---|---|---|
| `N_THREADS` (llamacpp on cpu) | about 25% of the cores, at least 2 | cores minus 2 |
| `N_PARALLEL` / `OLLAMA_NUM_PARALLEL` | 1 | chat: 2 on gpu, 1 on cpu; embed: 4 |
| `N_BATCH` (llamacpp) | 256 cpu / 512 gpu | 512 cpu / 2048 gpu |
| `N_CTX` (llamacpp chat) | sized so the KV cache takes at most half the memory left after the model, a power of two from 2048 to 32768 | same |
| GPU headroom in `fit` | `max(20%, 2 GB)` | `max(10%, 1 GB)` |

A llama.cpp placement also gets a container **memory limit** from the same
estimate `fit` makes (weights + KV cache + overhead, rounded up to 0.5 GB),
capped at half the node's RAM when `shared` and RAM minus 4 GB when
`dedicated`. A gpu placement never gets less than the agent's old 8 GiB (the
host side of a GPU model is not in the estimate); an unknown size keeps
that default. `place` prints the limit and `noo cluster desired` shows it
in the `mem` column. The CPU quota follows `N_THREADS`.

An explicit `--env KEY=VALUE` always wins, and a key the placement
already carries for the same model is kept; changing `--on` re-tunes.
Every key is on the node agent's placement allow-list
([node agent security](../security/node-agent.md#placement-env-allow-list)).

The usage profile is per node:

```sh
noo cluster set-config gpu-2 --usage shared      # someone also uses this box
noo cluster set-config gpu-2 --usage dedicated   # it exists to serve models
noo cluster set-config gpu-2 --usage default     # back to the default
```

Unset, the controller's own node is `dedicated` (it was built to run the
stack) and every other node is `shared` (a worker is often someone's
desktop or laptop). `noo cluster show` and `noo cluster desired` print the
profile and where it came from, and each placement's target.

### Place the harness

`place` also places the **harness** — the agent loop itself — next to a
node's chat backend:

```sh
noo cluster place gpu-2 harness auto          # point at whichever chat backend gpu-2 runs
noo cluster place gpu-2 harness qwen-7b.gguf  # point at that model's backend on gpu-2
```

### Declare what consumers may ask for

```sh
noo cluster class list
noo cluster class set chat-default node-1/vllm mac-1/ollama=gemma4:12b --degraded controller-1/ollama
noo cluster class set chat-default node-1/vllm mac-1/ollama=gemma4:12b --pool
noo cluster class unset chat-default
```

A **model class** is a name a consumer sends as `model` on
`/v1/chat/completions` or `/api/external/chat/completions`, and the ordered
list of `node/backend[=model]` candidates the gateway tries first.
`node/backend` with no `=model` means the placement's model (a class never
restates a placement); `--degraded` candidates come after the others. A
class is a preference, not a fence: when none of its candidates can
answer, every other live chat node follows in the dynamic ranking below,
and a model nothing serves is answered by `chat-default`. With nothing declared, every served model is its own class and
`chat-default` is **dynamic**: every live chat node in the mesh, whatever
model it serves, ranked per request — healthy before not, a node that
stalled in the last 5 minutes after one that did not, thermal
`serious`/`critical` after cooler, a GPU shared with another workload
after a free one, vLLM then a GPU runtime then CPU, the larger model first,
then fewest requests in flight and the lowest load. A quarantined or
thermal-`critical` node is left out unless nothing else is. Nodes come and
go: a busy, hot or offline node drops out and rejoins on its own. The
yaml's `cluster.backends.<x>.model` (what onboarding put on the local
backend) is a placement hint and does not narrow this. Declaring
`chat-default` puts your list ahead of the dynamic pool; `class list`
prints `chat-default: dynamic (all live chat nodes)` or `declared`, and
`noo cluster verify --controller` has a `default chat` row listing the live
candidates in order (`!` when only CPU candidates or one node remain, `x`
when none).

**Purposes.** Stack services name a purpose instead of a model:
trellion's answers and ingestion send `knowledge`, conversation
extraction sends `graph`. `class list` shows them as `(purpose)` aliases.
Undeclared, a purpose means `chat-default` (any live chat node) and is not
a fallback. To prefer a model for one, point the purpose at it; the mesh
still answers behind it when that model cannot:

```sh
noo cluster prefer                          # every purpose and what it prefers
noo cluster prefer knowledge gemma4:26b     # a served model (or a class) first
noo cluster prefer knowledge --clear        # back to any live chat node
```

To prefer one node for a request, name it: a `node` field in the body or an
`X-Noo-Node` header on `/v1/chat/completions`,
`/api/external/chat/completions` or `/api/inference` (`noo inference run
-n`). It is tried first; when it cannot answer, the pool does and the answer
says `fallback: true`. A name that is no node of this mesh is refused with
422. Add `node_strict: true` / `X-Noo-Node-Strict: 1` (`--strict-node`) to
keep the request on that node alone: a node serving no chat is then refused
with 422, one that does not serve the model you named with 409, and nothing
ever goes elsewhere. The `legacy lanes` row of
`noo cluster verify --controller` includes `cluster_hmac_v1`: the callers (a
node by name, from the gateway's counters and from each agent's heartbeat)
still signing the old, replayable cluster token instead of the request-bound
v2; it reads 0 once every node has upgraded, and only then is it safe to set
`NOO_CLUSTER_TOKEN_V1=0` (see the node-agent security page; the next
`noo cluster provision` / `noo upgrade --nodes` bundle then carries the closed gate to
every node). `noo cluster
verify --controller` has a `model classes` row for candidates that are neither
running nor pulled where they are declared.

`--pool` turns the list into peers instead of a failover order: each
request goes to the healthy candidate with the fewest requests the
gateway has open to it, then the lowest load, so one class spreads across
several nodes instead of queueing on the first. Pool members may serve
different models, because declaring the pool says they are
interchangeable. Failover and `--degraded` still apply. A consumer that
names a concrete model (`google/gemma-4-12B-…`) still reaches only the
nodes serving it, so pinning stays available.

Once the agent has started it, every turn whose model resolves to gpu-2
runs there: the loop calls the model next door and reaches the cluster
only through the gateway, as the person whose turn it is. Nothing changes
for the person; `noo cluster show gpu-2` lists `harness` with the rest.
No harness on a node, or one that does not answer, and the controller
runs the turn as before. `NOO_HARNESS_DISPATCH=0` on the controller is
the brake.

The controller's own node is no exception. The controller box also runs a
node agent for its own node (see
[../security/node-agent.md](../security/node-agent.md)), so
`noo cluster place <controller-node> harness auto` places a harness there
like anywhere else, and a turn for a model served on that node goes to it
once the agent reports the harness `running`. Until then, with no harness
placed or one placed but not running, the controller runs those turns in
process, and a task's `why` names which it was.

The harness can also follow a node's chat backend on its own:

```sh
noo cluster set-config gpu-2 --harness auto     # a harness wherever a chat backend runs
noo cluster set-config gpu-2 --harness manual   # the default: only an explicit placement
noo cluster set-config gpu-2 --harness off      # never on this node
```

With `auto`, the node's desired config carries a harness placement
whenever a chat backend is running there, and turns for that node's
model run on it. `off` keeps a declared harness stopped.

How many loops a task may spend resolves in three layers: what the
request named, else the node's default (`noo cluster set-config <node>
--loop-budget <n>`, `default` to clear), else the cluster's
(`NOO_TASK_LOOP_BUDGET`, 20 unless set). A node with a slow model gets a
smaller number; the task record shows which applied.

Which harness runs on a node is part of the placement: `--kind noo`
(the default, this gateway's own loop), `claude-code`, `copilot` or
`codex` (declared in `config/harness-kinds.json`). The
node agent checks the kind against the node's chat backend before
starting anything — Claude Code, Copilot CLI and Codex CLI run on every
node backend (the harness translates their wire to the node's), as does
our own loop — and refuses a foreign kind until its vendor CLI is
installed on the node
(the runner is the same `noo-gateway` for every kind), so the placement
reports compatibility at once.

A node can be born with its policy, so it is ready for a chat model
before it has one: `noo cluster provision <node> --harness auto`, or
`harness_policy: auto` under the node in the seed file. Nodes that say
nothing get the cluster default, `NOO_HARNESS_DEFAULT_POLICY` (manual
unless set) — set it to `auto` once and every node provisioned after
that follows its chat backend.

`place` writes a placement to the node's desired config
(`gpu-2: ollama → qwen2.5:7b-instruct (running) — agent reconciles within
5 min`); `--stopped` records it without starting, `--port`/`--tls`/`--image`
pin the container. `desired` shows the node's config row (ip, tier, ssh
user, data root, models dir, GPU override) and its placements
(`backend | model | port | tls | desired`). `unplace` removes the record
and leaves the container as-is. Node facts that the agent cannot detect
go in with `noo cluster set-config gpu-2 --tier 2 --gpu-model "RTX 4090"
--vram-gb 24` (the GPU override is inactive until **both** fields are set).

To declare the whole fleet at once, keep a seed file:

```sh
cp config/cluster-seed.yaml.example config/cluster-seed.yaml
noo cluster seed --dry-run
noo cluster seed
noo cluster seed --export > cluster-snapshot.yaml   # snapshot a live cluster in seed shape
```

Name the node yourself with `noo cluster place`; to steer which model a stack
purpose tries first use `noo cluster prefer`, and to let several nodes share
one model name use `noo cluster class set <class> ... --pool`. The old
planner verbs (`place-model`, `auto-place`, `reconcile-models`) are retired.

### Embedding spaces: one model per purpose

```sh
noo cluster embedding-space list
noo cluster embedding-space set code nomic-embed-code
noo cluster place gpu-2 ollama nomic-embed-code --role embed
```

Vectors from two embedding models cannot be compared, so embeddings never
fall back across models the way chat falls back across the mesh. The unit
is an **embedding space**: a purpose bound to one model. `knowledge`
(documents, memory, recall) exists from the first start, seeded with the
model the fleet already serves; add others, such as a `code` space with a
code embedder, beside it. A space's pool is every node whose role=embed
placement serves its model: the gateway spreads that space's requests across
the pool and never sends them to a node on another model, and a reply that
names another model is discarded and the next node tried. Callers send the
space as `model` on `/api/external/embeddings` (`knowledge` when absent).
An embed placement on a model no space uses is refused; a space's model does
not change by setting: that is a re-embed (below), or declare a new space.
A node may serve several spaces: place each model as its own embed row
(`noo cluster place gpu-2 ollama harrier --role embed`, then the code model
the same way) and the node joins each space's pool. Placing a second embed
model on ollama adds a row; chat and rerank placements still replace the
role's one row, and a backend other than ollama (TEI, llama.cpp) holds one
embed model, so a second replaces the first. Remove one embed model with
`noo cluster unplace gpu-2 ollama --role embed --model nomic-embed-code`.

**Re-embedding a space into a new model.** `noo cluster embedding-space migrate
knowledge bge-m3` starts it. The gateway first probes the new model (one short
text, over the nodes that run it) and refuses if the vector width differs from
the space's: trellion's vector columns are `vector(1024)`,
and a model of a different width needs the columns retyped, which is not
built. While the migration is `filling`, nothing changes for readers or
writers: trellion embeds every stored row again with the new model
(`knowledge@next`) into a second column beside the live one, and reports
progress, which `embedding-space list` and `noo cluster verify` show. If no node serves
the model yet the migration is `pending` (the command answers 202): place the
model with `noo cluster place <node> ollama <model> --role embed` (allowed
because a migration names it) and the gateway re-probes about every 15 seconds
and starts the migration by itself; a width mismatch found then keeps it
pending and is shown as the reason. trellion acts only on `filling` and
`cutover`.
When every table reports done == total (and trellion has reported in the last
10 minutes), `migrate knowledge --complete` begins the cutover: trellion swaps
the new vectors into place table by table and reports `cutover_done`, and only
then does the space's model change, in one step. Rows trellion cannot embed
again (no stored source text, e.g. concept centroids, or a row the embedder
rejects on its own) are counted as `unsourced` and get no new vector at the
cutover, and `embedding-space list` says how many. Text chunks and episodes
keep their old vector, still labelled with the old model so no search under
the new model reads it, until trellion's stale sweep re-embeds them (episodes
copy from their healed record); entities are removed and cluster centroids
cleared, and whatever owns them regenerates them on its next run. Rows
written under an old model later (a writer racing the cutover) are found and
re-embedded by trellion's stale sweep. `migrate knowledge --cancel`
abandons a `pending` or `filling` migration and leaves the live vectors untouched; once the
cutover has begun it cannot be cancelled. A space with a migration cannot be unset until it is cancelled.

### Get a model onto the fleet

```sh
noo models recommended                      # per detected tier; prefers LAN-cached models
noo models info Qwen/Qwen2.5-7B-Instruct    # gating, licence, formats
noo models pull qwen2.5:7b-instruct         # through the gateway's Ollama proxy, streamed progress
noo models cached                           # what running backends have loaded
noo models fetch <org>/<repo> <file.gguf>   # GGUF from Hugging Face into the controller store (resumable, sha256-verified)
```

To convert a Hugging Face model to GGUF and install it on one node:

```sh
noo cluster ship-model Qwen/Qwen2.5-7B-Instruct gpu-2 --quant Q4_K_M --place
```

That runs `scripts/noo-model-convert.sh` on the controller, publishes the
GGUF and Modelfile to the controller's artifact store and asks the node's
agent to fetch them and `ollama create` (no SSH or scp); `-b <backend>`
(default `embedding`) and `--name` shape the import, and `--place` also
records a placement. `noo cluster sync-model-files gpu-2 -m model.gguf`
dispatches a job per node that pulls existing GGUF files from the
controller's model store (`$MODELS_DIR`, else `$NOO_DATA_ROOT/models`) and
verifies them; `--dry-run` only plans. `--user` is refused.
Catalog reads (`list`, `search`, `ollama`, `huggingface`) use a 24-hour
local cache with offline fallback; `noo models refresh` rebuilds it.
See [weight-cache.md](../models/weight-cache.md).

### Run a prompt or a job

```sh
noo inference run "Summarise this in one line: …" -m qwen2.5:7b-instruct
noo inference agent "Which nodes are idle and why?" --max-iters 6
noo jobs run "…" --priority 8            # queue it; polls every 2 s until terminal
noo jobs run "…" --async                 # print the id and return
noo jobs status <job-id> --wait
noo jobs list --watch
```

`inference run` posts to `/api/inference` and prints the response.
`-n <node>` names the node to try first: when it cannot answer, the pool
does and the CLI says so (`! answered by <model> — <node> could not:
…`). `--strict-node` keeps the prompt on that node alone and fails
when it cannot answer — for locality or privacy, or a liveness check;
`inference agent` runs the coordinator loop with tools (`--no-tools`
disables them). A job that ends in any state other than `completed` exits
1. `jobs scheduler` shows dispatch counters; `jobs pause`/`resume` stop and
restart dispatch; `jobs drain <node>` stops sending a node work while
its running jobs finish, `undrain` reverses it. `jobs cancel` asks for
confirmation.

### Upgrade the fleet's agents

```sh
noo cluster upgrade-hostd gpu-2 gpu-3      # the root helper, named nodes only
noo cluster upgrade-agents                 # every online remote worker, serially
```

Both travel the pull rail in bundles signed by the fleet signing key — no
SSH. `upgrade-hostd` cross-builds per architecture and delivers a signed
`hostd-binary` bundle (`collected — node-side apply is the verdict from
here`); the applier keeps `.prev` and reverts a hostd that produces no fresh
heartbeat. `upgrade-agents` restages each node's provision bundle (the
agent binary rides in it) with `noo cluster provision <node> --wait`, one
node at a time, and reports each node's apply verdict; a failed node keeps
its previous state and the roll moves on. Pass node names to limit it.
It used to drive a separate swap — the agent pulled a binary
whose manifest the **gateway** signed, and hostd installed it as root — so a
compromised gateway could reach every node. That lane is retired: the
gateway refuses the manifest, the agent refuses `/pull kind=binary` (410),
hostd refuses `swap-agent`, and `--skip-build`, `--drain-grace` and
`--health-timeout` are accepted and ignored with a note.
`noo cluster upgrade-applier <node>...` refreshes
the node-side `noo-apply`; `noo cluster restart-backends gpu-2 noo-ollama`
restarts named `noo-*` containers through the same rail. `noo upgrade
--nodes` (Setup & host) restages the whole bundle instead.

### Push a rotated fleet secret

```sh
noo cluster push-secrets --explain
noo cluster push-secrets --dry-run
```

One direction only: it moves each node toward the value the controller
already runs (`NOO_CLUSTER_SECRET`, `NOO_NODE_AGENT_TOKEN` — the fixed
fleet-key set; there is no `--key` flag. The shared `NATS_USER` /
`NATS_PASSWORD` pair left it when the shared bus user was retired: a node's bus credential is
its own, delivered by `noo cluster nats-creds rotate <node>`). It
reads the controller value from `secrets/env.sops`, checks it against the
live gateway's env, and for every key the gateway agrees with, stages a
CA-signed `fleet-secrets` bundle — a dotenv fragment, end-to-end encrypted
to each node's birth cert — on the pull rail. Each node's applier merges
the fragment into `/etc/noo-node-agent.env` and restarts the agent, which
reconnects presenting the controller's value. A key the gateway disagrees
with, cannot confirm, or does not hold is refused and reported rather than
guessed at. `--dry-run` shows what would be staged without writing
anything; `--explain` prints why an online rotation isn't possible today,
with no network call. Change the controller side first: `noo security secrets rotate`
refuses these keys, so mint a value with `noo security generate-secret
cluster`, set it with `sops secrets/env.sops` and restart the stack
([security.md](security.md#rotate-a-secret)).

### Tear a node down

```sh
noo cluster teardown-node gpu-2                    # dismantle the agent, keep data and tailnet membership
noo cluster teardown-node gpu-2 --factory -y       # also purge data and leave the tailnet
```

The command confirms, stages a CA-signed `teardown` bundle on the pull
rail — there is no fallback lane; a node with no birth cert on record
predates the rail and must be re-enrolled first — waits up to four
minutes for the node to fetch it, then **verifies silence** — polls until
the node stops heartbeating
(`gpu-2 stopped heartbeating: dismantle confirmed`). A node still
heartbeating after that is reported loudly with the node-side recovery
(`sudo noo-deenroll`). Finally it removes the node's certs and inventory
line and, with `--purge-tailscale`/`--factory`, deletes the tailnet
device. For a node that is already gone (hardware dead, never coming
back), skip the bundle:

```sh
noo cluster forget gpu-2
```

`gpu-2 forgotten — node row + mesh entry removed; registration is
first-contact again`. Forgetting a **live** node does nothing useful — it
re-registers on its next heartbeat.

### Watch the engine that runs the fleet

```sh
noo autonomy status          # engine state and every configured location
noo autonomy audit -n 50     # what it decided recently
noo autonomy disable         # stop the patrols (re-enable with enable)
```

Locations, conditions and actions are listed by `noo autonomy locations`. If a backend keeps
refusing to start after an outage, `noo cluster clear-cooldowns` resets
the auto-start backoff (the gateway clears every node regardless of the
argument).

### Run and write a sandboxed skill

```sh
noo skills list
noo skills run text_summarizer '{"text":"…","style":"bullet_points"}' -n gpu-2
noo skills scaffold my-skill
```

`list`/`info` scan `skills/builtins/` in the checkout and your user dir
(`$NOO_SKILLS_DIR`, else `~/.noo/skills`, which overrides builtins by
name) — no gateway call. `run` goes through the gateway
(`/api/skills/{name}/run`): the gateway builds the container spec from the
manifest (image, command, `SKILL_INPUT`, memory/network/GPU limits) and
posts it to a node agent's `/api/skills/run` with the controller's
certificate. It runs skills from the gateway's own registry, so a skill
that exists only in your user dir is not found there. `-g` is still
accepted and changes nothing.
`scaffold` writes `manifest.yml` + `run.py` with the tightest defaults (no
network, no filesystem, no shell) — the sanctioned way to add code an
agent may execute.

### Shared GPU nodes

A node can be a person's machine as well as a mesh node: the same box plays
VR, trains models, or runs a realtime voice stack. When something **outside
noomesh** needs the GPU, the node agent does not stop. It stays online, gives
the GPU back, says so, and takes it again on its own once the GPU is free.

**What counts as foreign.** A GPU process is noomesh's when it runs in a
any noomesh container on the host: the agent's backends, the compose-managed
controller stack (`noo-ollama-embed`, `noo-tei`, ...) and older leftovers.
Containers are recognised by their labels (compose project `noomesh` or
`pai-assistant`, `noo.managed-by`), with the `noo-` name as the fallback; a
container recognised only by name is reported as `orphan`. Everything else
(another compose stack, a game, a training script) is foreign. The agent only
measures foreign work. It never signals, stops or reconfigures it. Memory it
cannot attribute (docker unreachable, a process gone) is `unknown_mb`, is never
counted as foreign and never yields; the method then reads
`nvidia-smi-unattributed` and `reason` says so.

**How it measures.** Every 15 s it reads `nvidia-smi` (`memory.used`,
`memory.total` and the compute processes). When the process IDs resolve, each
one is matched to a managed container through its cgroup (method
`nvidia-smi`). Under WSL2 the process rows read `[Not Found]`, so the agent
falls back to accounting: foreign = memory used − the expected footprint of
the GPU backends it is running (vLLM: `GPU_MEMORY_UTILIZATION` × total)
(method `memory-accounting`). A Mac or a node without an NVIDIA GPU reports
`not-measured` and never yields.

**When it yields.** The GPU is under pressure when foreign use is above
`NOO_GPU_YIELD_FOREIGN_MB`, or when what is left after foreign use is less
than the placed GPU backends need. Once the pressure has lasted 60 s, the
agent **stops** (does not remove) its GPU backend containers and marks them
`paused: gpu_in_use_by_other`. The reconciler does not start a paused backend
again. Once the GPU has stayed clear for `NOO_GPU_RESUME_AFTER_S`, the agent
starts the same containers again. A short spike does not pause anything, and
a relapse during the clear window starts the window over. A drained stack's
idle residue (pai-voice leaves about 113 MiB) counts as free.

**What routing sees.** The node keeps heartbeating, so it stays in the mesh.
The paused backend is simply not running, so default chat goes to other
nodes. When the backend resumes, the node rejoins.

**Hand the GPU over on purpose.** With automatic yielding alone, whichever
side starts first keeps the GPU, and a stack that refuses to start on a busy
GPU never gets it. An operator hold settles that:

```bash
noo cluster gpu hold host3 --reason voice   # drains, then pauses host3's GPU backends; no auto-resume
#   ✓ host3: GPU held (voice) — vllm paused; it stays paused until you release it
#   lease: operation 7c1e…, generation 4, drained first
pai-voice-gpu enable                        # on host3: the voice stack now finds the GPU free
# ... later
pai-voice-gpu disable                       # the voice stack drains and frees the GPU
noo cluster gpu release host3 --operation 7c1e… --generation 4   # back to automatic: vLLM resumes once the GPU stays free
```

`hold` and `release` are operator-only and audited (`node_gpu_hold`,
`node_gpu_release`). A hold survives an agent restart. Nothing flows in the
other direction: the other stack never calls noomesh.

**A hold drains first.** From the moment the gateway accepts the hold the
node's lanes get no new request; the agent closes admission on its GPU
backends (a request that still arrives is answered `503 backend_draining`
at once and the gateway serves it elsewhere) and waits for every request in
flight on them to finish, up to `--timeout` (default 120 s, max 900). Only
then are the backends stopped. If something is still running at the
timeout the hold is **not** applied: admission reopens, nothing was
stopped, and the command fails with `drain_timeout` naming the backends and
counts still busy. Nothing in flight is ever cut by a drain hold.
`--immediate` is the old behaviour (stop after a 30 s grace, requests in
flight included): for emergencies, and the output says what it did.

**A hold is an owned lease.** Every hold carries an operation id (yours
with `--operation`, else a fresh UUID) and is given the node's next
`generation`; the output prints both and the exact `release` line. A
release quotes them (compare-and-set): a release with the wrong pair, a
stale retry, or a release of a node held by another operation is refused
(`held_by_other`, naming the current lease) and changes nothing. A hold on
a node another operation holds is refused the same way. `--force` on either
takes over or ends any hold and is audited as a force; a bare
`noo cluster gpu release <node>` is a force too (the operator's hand). One
hold or release runs per node at a time (`transition_in_progress`).
`release --now` restarts the paused backends at once instead of waiting
for the GPU to stay clear for `NOO_GPU_RESUME_AFTER_S`.

An older CLI's bare `hold` (no operation id) still works for an operator:
it is immediate and a force, and the audit row says `legacy`.

### Reservations: a feature takes a GPU, the pool gets it back

A feature that must continuously consume a piece of the mesh (voice while
voice is on; an image or video worker with its model loaded) **reserves** a
GPU. The workload is what an add-on's verified bundle declares
(`<addon>/<workload>`: its container, whether it takes the GPU and how much,
its own drain route); core never names one. `noo cluster gpu hold|release`
stay as the low-level emergency tools underneath.

```bash
noo cluster workloads                              # what the installed add-ons declare
noo cluster reserve pai-voice/voice-worker         # the mesh picks a node: any live node with enough free GPU memory
noo cluster reserve pai-voice/voice-worker --node awolf   # or pin one
noo cluster reservations                           # id, workload, holder, node, state, since
noo cluster release <reservation-id>               # the GPU returns to the pool
```

Taking a reservation: an owned GPU hold in mode drain (the pool's requests
in flight on that GPU finish, nothing is cut; its backends pause), then the
node agent starts the declared container, then the command waits for it to
run (and pass its healthcheck when it has one). A start that fails gives the
GPU back at once; a container that is not ready in time keeps the
reservation and the command says `needs_attention`. Releasing: the add-on's
declared drain route runs first (its sessions end on its own terms), the
container stops, and the hold is released by compare-and-set with an
immediate resume. Only the holder releases, or an operator with `--force`
(audited). `--hand-over <reservation-id>` moves a GPU from one workload to
the next on the same node without the pool getting it in between.

The reservation **is** the node's GPU lease: its id is the lease's operation
id, so nothing is stored twice and `reservations` reads the nodes'
heartbeats. While a workload is reserved, its add-on reaches it through
`/api/addon-workloads/<addon>/<workload>/proxy/<path>` (requests and
WebSockets; the add-on's own token for its own workloads, or an operator):
the gateway resolves the reservation's node, the node agent proxies to the
container's published loopback port. A relayed WebSocket closes with code
4001 when the reservation ends. Nothing else on the node is reachable that
way, and a workload that is not reserved answers 409.

**Knobs** (operator overrides in `/etc/noo-node-agent.env`; restart the agent):

| Variable | Default | Meaning |
|---|---|---|
| `NOO_GPU_YIELD` | on | `off` never yields automatically (always run). An operator hold still works |
| `NOO_GPU_YIELD_FOREIGN_MB` | `2048` | foreign GPU use above this is pressure |
| `NOO_GPU_YIELD_AFTER_S` | `60` | how long pressure must last before the agent yields |
| `NOO_GPU_RESUME_AFTER_S` | `120` | how long the GPU must stay clear before the agent resumes |

**What the operator sees.** The heartbeat carries `gpu_contention`:

```json
{"state": "yielded", "foreign_mb": 11468, "noomesh_mb": 3754, "unknown_mb": 0, "total_mb": 16376, "free_mb": 4908,
 "method": "memory-accounting", "since": "2026-10-17T12:00:00Z",
 "paused_backends": ["vllm"], "need_mb": 14738,
 "reason": "foreign GPU use 11.2 GB > 2.0 GB threshold", "policy": "auto"}
```

`state` is one of `free`, `shared` (foreign work beside running backends),
`yielded`, `draining` (a hold waiting for requests in flight) or `held`.
`generation` counts the node's accepted holds; while draining or held,
`lease` carries `{owner, operation_id, generation, mode, reason, since,
drain_started, drained_at}`.

- `noo cluster status` prints `! host3: GPU in use by other work — vllm paused since <t> (foreign 11.2 GB)`.
- `noo cluster verify host3` has a `control over bus` row: one `health` round
  trip over NATS. It is a warning reading `NOT CHECKED` (never ok) for a node
  that does not advertise `nats_rpc`, which keeps taking control calls over
  HTTPS :8081; a node that advertises it and does not answer FAILS, with
  `noo cluster nats-users render` as the first remedy. See
  [Control over the bus](../security/node-agent.md#control-over-the-bus).
- `noo cluster verify host3` has a `streaming over tunnel` row: one stream
  round trip over the node's outbound tunnel, with the per-node counts of
  streams carried by the tunnel and by HTTPS. It is a warning reading
  `NOT CHECKED` (never ok) for a node that does not advertise a tunnel, which
  keeps taking streaming calls over HTTPS :8081; a node that advertises one
  while the gateway holds none, or gets no answer, FAILS. See
  [The node-held tunnel](../security/node-agent.md#the-node-held-tunnel).
- `noo cluster verify host3` has a `gpu` row: `+ free`, or
  `! yielded: vllm paused (foreign 11.2 GB, memory-accounting)`. Yielded and
  held are warnings, not failures, because the node is working as designed.
- The console's node card shows "GPU in use by other work — vllm paused since …".

## Related guides

- [../models/weight-cache.md](../models/weight-cache.md) — the LAN model-weight cache

## Command reference

<!-- BEGIN GENERATED: cli-reference section="Fleet" — do not edit; regenerate with scripts/gen-cli-docs.py -->
### `noo cluster` — Node management, provisioning (bootstrap-token + pull rail), teardown
| Command | Arguments | What it does |
|---|---|---|
| `noo cluster status` | — | List nodes: tier, status, RUNNING backends, CAPABILITIES by role, CAN-RUN |
| `noo cluster verify` | `[<node>...] [--controller] [--wait]` | Assert every invariant a node and the controller must meet; exit 1 with the remedy |
| `noo cluster invite` | — | Mint a tagged tailscale auth key and print the `noo enroll --via-tailnet <url>` line |
| `noo cluster down` | `<backend> [--node <node>] [-y\|--yes]` | Stop a backend on one node or all nodes; destructive, asks for confirmation (-y) |
| `noo cluster desired` | `<node>` | Alias of show: the node in full, with its desired config and every placement |
| `noo cluster proposals` | `[--status <s>] [--limit <n>]` | List the enrollment proposals agents filed, with each host in full |
| `noo cluster show` | `<node>` | Show one node in full: hardware, agent version, tier drift, bus principal, roles |
| `noo cluster forget` | `<node> [--purge-tailscale] [-y\|--yes]` | Remove a dead node's row, KV entry and enrollments; --purge-tailscale drops its device |
| `noo cluster place` | `<node> <backend\|harness> <model\|auto> [--on cpu\|gpu] [--env KEY=VALUE]... [--kind noo\|claude-code\|copilot\|codex] [--role chat\|embed\|rerank] [--port <port>] [--tls] [--image <image>] [--stopped] [--force]` | Declare a backend and model in a role on a node, on cpu or gpu; auto-tunes unless --env |
| `noo cluster unplace` | `<node> <backend> [--role chat\|embed\|rerank] [--model <model>]` | Remove a placement, or one embed model; a container keeps running, a harness is stopped |
| `noo cluster fit` | `<node> [--with <backend> <model> [--on cpu\|gpu] [--role <role>] [--env KEY=VALUE]...]` | Show whether placements fit a node's GPU memory and RAM, with or without one more |
| `noo cluster class list` | — | Show the model classes consumers may send as `model`, with candidate placement and health |
| `noo cluster class set` | `<class> <node>/<backend>[=<model>]... [--degraded <node>/<backend>[=<model>]]... [--alias <name>]... [--pool]` | Declare a model class: failover order, or --pool to share the load; --degraded ones last |
| `noo cluster class unset` | `<class>` | Forget a declared model class and its aliases; the derived class of its model takes over |
| `noo cluster prefer` | `[<purpose> <model\|class> \| <purpose> --clear]` | Show or set which model a stack purpose (knowledge, graph) tries first |
| `noo cluster embedding-space list` | — | Show each embedding space, its model and the nodes serving it |
| `noo cluster embedding-space set` | `<space> <model> [--dims <n>]` | Declare an embedding space: a purpose bound to one embedding model |
| `noo cluster embedding-space unset` | `<space>` | Forget an embedding space; the default (knowledge) cannot be removed |
| `noo cluster embedding-space migrate` | `<space> <model> \| <space> --complete \| <space> --cancel` | Re-embed a space into a new model: start, complete or cancel |
| `noo cluster logs` | `[<node>] [<service>] [-b\|--backend <backend>] [-n\|--tail <n>]` | Tail logs for a noo-* container or host service (harness, agent) on one node or all |
| `noo cluster restart-agent` | `<node>` | Ask the gateway to restart a node's node-agent |
| `noo cluster maintenance` | `<node> on --reason <text> [--until <duration>] \| <node> off \| list` | Mute a known-down node's operator alerts (operator-only); the daily summary still lists it |
| `noo cluster gpu hold` | `<node> [--reason <text>] [--operation <id>] [--timeout <secs>] [--immediate] [--force]` | Drain, then pause a node's GPU backends, held as an owned lease until released (operator) |
| `noo cluster gpu release` | `<node> [--operation <id> --generation <n>] [--force] [--now]` | End a GPU hold by its lease (or any with --force); backends resume when free, or now |
| `noo cluster reserve` | `<addon>/<workload> [--node <node>] [--hand-over <reservation-id>] [--timeout <secs>]` | Reserve a GPU for an add-on workload: drain the pool there, pause it, start the workload |
| `noo cluster reservations` | — | List the GPU reservations the nodes hold: id, workload, holder, node, state |
| `noo cluster release` | `<reservation-id> [--force]` | Release a reservation: drain and stop the workload, give the GPU back (holder or --force) |
| `noo cluster workloads` | — | List the workloads the installed add-ons declare (container, GPU need, drain route) |
| `noo cluster profile` | `<node> [--set <key=value>]... [--clear <key>]... [--clear-all] [--bench]` | Show a node's harness profile with each value's source; set overrides; bench its model |
| `noo cluster init-secret` | — | Generate and print a fresh random cluster secret locally (no gateway call) |
| `noo cluster set-config` | `<node> [--usage shared\|dedicated\|default] [--harness auto\|manual\|off] [--loop-budget <n>\|default] [--data-root <path>] [--models-dir <path>] [--ip <ip>] [--tier <n>] [--gpu-model <model>] [--vram-gb <n>] [--min-battery <pct>] [--require-wifi <bool>] [--block-thermal <s,s>] [--policy-default] [--vendor-kinds <kind,kind>\|none]` | Update a node's stored config row with only the given fields |
| `noo cluster clear-cooldowns` | — | Clear backend auto-start cooldown backoff on every node |
| `noo cluster teardown-node` | `<node> \| --all [--purge-data] [--purge-tailscale] [--factory] [-y\|--yes]` | Dismantle one node or --all via a signed teardown bundle, verify silence, then forget |
| `noo cluster provision` | `<node> [<tier>] [--harness auto\|manual\|off] [--wait [<secs>]] [--stage-only] [--move-data]` | Stage a node's signed bundle; --wait blocks until enrolled, --stage-only skips the apply |
| `noo cluster sync-model-files` | `[<node>...] [-m\|--model <file>]... [--dry-run]` | Dispatch a job per node to pull GGUF weights from the controller store and verify them |
| `noo cluster bootstrap-token create` | `[--ttl <1h\|30m\|24h\|secs>] [--role <role>] [--cidr <cidr>] [--node <name>] [--with-tailscale\|--no-tailscale]` | Mint a single-use enrollment token and print the node enrollment one-liner |
| `noo cluster bootstrap-token list` | — | List bootstrap tokens with status, creator, expiry and redeeming IP |
| `noo cluster bootstrap-token revoke` | `<id>` | Revoke a bootstrap token by id (idempotent) |
| `noo cluster bootstrap-token` | — | Print bootstrap-token subcommand usage (create, list, revoke) |
| `noo cluster set-primary` | `[--to <target>] --promoted [-y\|--yes]` | Move the primary-controller role; promote Postgres on the target first, then --promoted |
| `noo cluster sync-images` | `[<node>...] [-i\|--image <img>]... [--images <a,b>] [--restart\|--no-restart] [--all] [--stage-only] [--lock] [--arch <a,b>] [--all-images]` | Stage images on the artifact rail, then nodes pull them (--stage-only: stage, no pull) |
| `noo cluster upgrade-agents` | `[<node>...] [-y\|--yes]` | Restage node agents serially in signed bundles over the pull rail; asks to confirm (-y) |
| `noo cluster upgrade-hostd` | `<node>... [--skip-build] [-y\|--yes\|--force]` | Roll noo-hostd to the named nodes over the pull rail as a signed bundle |
| `noo cluster upgrade-applier` | `<node>... [-y\|--yes\|--force]` | Ship the current noo-apply to nodes over the rail; asks for confirmation (-y) |
| `noo cluster restart-backends` | `<node> <noo-svc>... [-y\|--yes\|--force]` | Restart noo-* backend containers on a node via a rail-delivered bundle |
| `noo cluster host-telemetry apply` | `[<node>...] [--all] [--include-controller] [-y\|--yes]` | Switch off tailscaled's log upload on nodes over the pull rail, one at a time |
| `noo cluster host-telemetry` | — | Print host-telemetry subcommand usage (apply) |
| `noo cluster vendor stage` | `[<kind> [--fleet] \| --all] [--os linux\|macos] [--arch x86_64\|aarch64]` | Fetch the vendor CLIs the nodes need on the controller, checked against their pins |
| `noo cluster vendor status` | — | List staged vendor CLIs per platform, and which nodes need which |
| `noo cluster vendor install` | `<node> <kind>...` | Carry these vendor CLIs on a node whatever its placement names; restage to deliver |
| `noo cluster vendor` | — | Print vendor subcommand usage (stage, status, install) |
| `noo cluster push-secrets` | `[<node>...] [--dry-run] [--explain] [--gateway-container <name>] [--sops-file <path>] [-y\|--yes]` | Stage fleet-wide secrets from env.sops as a bundle each node collects |
| `noo cluster nats-users render` | `[--rotate] [--dry-run] [-y\|--yes]` | Mint per-principal NATS passwords from the gateway registry and render users.conf |
| `noo cluster nats-creds rotate` | `<node\|gateway\|worker\|trellion\|trellion_intel>... [--mint-only] [--restart] [-y\|--yes]` | Rotate a bus credential: nodes deliver over the rail; others re-render + recreate |
| `noo cluster import-model` | `<node> <name> [--place] [--role chat\|embed\|rerank] [-b\|--backend <backend>]` | Import a store model or a staged ollama:<tag> into a node's ollama |
| `noo cluster ship-model` | `<hf_id> <node> [--name <name>] [--quant <quant>] [--place] [-b\|--backend <backend>]` | Convert an HF model to GGUF and have a node import it; needs a source checkout |
| `noo cluster clean` | `<node>\|all [--deep] [-y\|--yes]` | Remove this stack's containers on node(s) through their agents; --deep removes images too |
| `noo cluster seed` | `[-f\|--file <path>] [--export] [--dry-run]` | Apply (or export) the cluster desired state from config/cluster-seed.yaml |

### `noo models` — Model catalog, search, pull, recommended
| Command | Arguments | What it does |
|---|---|---|
| `noo models cached` | — | List models currently loaded on running node backends |
| `noo models pull` | `<model> [--backend <b>]` | Pull onto the gateway's Ollama; whisper:<size> / piper:<voice> stage a voice model |
| `noo models fetch` | `<hf_repo> <file.gguf> [--revision <rev>] [--force]` | Download a GGUF from Hugging Face, or stage ollama:<tag> from the registry, into the store |
| `noo models list` | `[--backend <b>] [--tier <n>] [--limit <n>] [--refresh]` | List popular models per backend from the HuggingFace catalog cache |
| `noo models search` | `<query> [--backend <b>] [--limit <n>]` | Search HuggingFace for models, with cached offline fallback |
| `noo models info` | `<model>` | Show detailed HuggingFace info for a model, including gating hints |
| `noo models recommended` | `[--tier <n>] [--arch <a>] [--refresh]` | Recommend models for a hardware tier, auto-detected from the cluster |
| `noo models ollama` | `[--limit <n>] [--refresh]` | List popular Ollama-compatible models from the catalog |
| `noo models huggingface` | `[<query>] [--limit <n>]` | Search HuggingFace models (default query "mistral instruct awq") |
| `noo models switch` | `<model> [--backend <b>] [-y\|--yes]` | Switch the active model: rewrites .env/noomesh.yaml, restarts; asks (-y) |
| `noo models refresh` | `[--backend <b>] [--llm]` | Rebuild the model catalog cache from HuggingFace, bypassing the TTL |

### `noo tools` — Cluster tool registry
| Command | Arguments | What it does |
|---|---|---|
| `noo tools list` | `[--node <node-id>]` | List registered cluster tools (base/specialized shown only when reported), or one node's |
| `noo tools select` | `<prompt>` | Hidden: retired, it previewed a matcher the agent does not use |
| `noo tools info` | `<tool-name>` | Show one tool's registry entry |
| `noo tools export` | `[-o <path>] [--check] [--force]` | Write the full tool registry to config/tools.json; --check diffs without writing |

### `noo inference` — Run prompts on the GPU cluster
| Command | Arguments | What it does |
|---|---|---|
| `noo inference run` | `<prompt> [-m <model>] [-b <backend>] [-n <node> [--strict-node]] [-u <user>] [--max-tokens <n>] [-t <temperature>]` | Run one direct model inference through the gateway and print the response |
| `noo inference agent` | `<prompt>` | Run a prompt through the gateway agent runner and print the response |

### `noo jobs` — Job queue & scheduler management
| Command | Arguments | What it does |
|---|---|---|
| `noo jobs list` | `[--limit <n>] [--status <s>] [--node <id>]` | List queued and running jobs from the gateway job queue |
| `noo jobs run` | `<prompt> [--async] [--priority <n>] [--backend <b>] [--node <id>] [-t <secs>] [--type <type>]` | Submit an inference job and poll until it finishes unless --async |
| `noo jobs status` | `<job-id> [--wait]` | Show one job record, optionally polling until it reaches a terminal state |
| `noo jobs submit` | `[--type <t>] [--priority <n>] [--backend <b>] [--payload <json>]` | Submit a job with a raw JSON payload and print its id (a prompt: jobs run --async) |
| `noo jobs history` | `[--limit <n>]` | Show recently completed jobs with status and duration |
| `noo jobs cancel` | `<job-id> [-y]` | Cancel a job; destructive, asks for confirmation (-y) |
| `noo jobs reprioritize` | `<job-id> <priority>` | Change a queued job's priority |
| `noo jobs scheduler` | — | Show job scheduler status and counters |
| `noo jobs pause` | — | Pause the job scheduler |
| `noo jobs resume` | — | Resume the job scheduler |
| `noo jobs drain` | `<node-id>` | Drain a node so the scheduler stops sending it jobs |
| `noo jobs undrain` | `<node-id>` | Undrain a node so the scheduler sends it jobs again |

### `noo autonomy` — Autonomy engine monitoring & control
| Command | Arguments | What it does |
|---|---|---|
| `noo autonomy status` | — | Show autonomy engine state and its configured locations |
| `noo autonomy locations` | — | Hidden: same as autonomy status |
| `noo autonomy audit` | `[-n <limit>]` | List recent autonomy audit entries (default 20) |
| `noo autonomy decisions` | `[-n\|--limit <n>] [-l\|--location <name>]` | What the disarmed autonomy locations would have done — the evidence for arming one |
| `noo autonomy enable` | — | Enable the autonomy engine |
| `noo autonomy disable` | — | Disable the autonomy engine |

### `noo skills` — Containerized skill management
| Command | Arguments | What it does |
|---|---|---|
| `noo skills list` | — | List containerized skills from the local registry dirs (no gateway) |
| `noo skills info` | `<name>` | Show one skill's full manifest from the local registry scan |
| `noo skills run` | `<name> <input-json> [-n <node>]` | Run a skill in its sandbox container through the gateway, on the node it picks or -n |
| `noo skills scaffold` | `<name> [-d <dir>]` | Generate a skill skeleton (manifest.yml + run.py) in the user skills dir |

### `noo browser` — Browser automation
| Command | Arguments | What it does |
|---|---|---|
| `noo browser status` | — | List active browser-automation sessions |
| `noo browser open` | `<url> [-n <node>]` | Navigate a browser-automation session to a URL and print title plus text preview |
| `noo browser stop` | `[<session-id>]` | Stop one browser session, or every session when no id is given |
<!-- END GENERATED -->
