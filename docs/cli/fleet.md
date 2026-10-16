# Fleet

Covers: node management, provisioning (bootstrap-token + pull rail) and teardown (`cluster`), the model catalog and pulls (`models`), the cluster tool registry (`tools`), running prompts on the GPU cluster (`inference`), the job queue and scheduler (`jobs`), the autonomy engine (`autonomy`), containerized skills (`skills`) and browser automation (`browser`).

Does not cover: the Docker stack on THIS host (`noo stack`), or memory and the knowledge base (`noo memory`, `noo rag`).

## Disambiguation

- `noo cluster` is the **fleet**: nodes, their desired state, enrollment and teardown. `noo stack` (Stack & data) is the Docker stack on **this host** — start, stop, rebuild, clean.
- `noo cluster place` **declares** that a node should run a backend with a model and lets the node-agent converge to it; `noo cluster up`/`down`/`scale` are the older **imperative** start/stop calls and are not remembered across an agent restart.
- `noo inference run` sends one prompt straight to a backend; `noo inference agent` runs the coordinator's full agentic loop (plan, tools, reflect); `noo jobs run` queues the prompt through the scheduler and polls the job. `noo chat` (Agents & channels) is the streaming conversation.
- `noo models` is the **catalog** (search, info, recommendations, pull through the gateway's Ollama proxy); getting a model onto a **specific node** is `noo cluster ship-model`, `sync-model-files` or a placement.
- `noo autonomy` is the self-healing engine (condition → action patrols); `noo heartbeat` (Stack & data) is the cron scheduler for user-facing tasks.
- `noo skills` runs **containerized code** in a sandbox on a node; `noo prompt-skills` (Memory & knowledge) are prompt templates; `noo tools` is the gateway's registry of the tools an agent may call.
- `noo cluster clean-node` is retired: it reported success while doing nothing on a pull-enrolled node, then de-registered it. Use `noo cluster teardown-node <node>` to dismantle, `noo cluster forget <node>` for a dead node, or `sudo noo-deenroll` on an orphaned node. `noo cluster add-node` was removed (2026-09-03) — it drove Ansible playbooks that no longer ship; enrol with a bootstrap token and finish with `noo cluster provision`. `noo cluster assign` without `--dry-run` calls a route the gateway no longer serves.

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
noo cluster class unset chat-default
```

A **model class** is a name a consumer sends as `model` on
`/v1/chat/completions` or `/api/external/chat/completions`, and the ordered
list of `node/backend[=model]` candidates the gateway fails over across.
`node/backend` with no `=model` means the placement's model (a class never
restates a placement); `--degraded` candidates are the only ones allowed to
answer with a different model, and only once every other candidate has
failed. With nothing declared, every served model is its own class and
`chat-default` is the configured default model. `noo cluster verify
--controller` has a `model classes` row for candidates that are neither
running nor pulled where they are declared.

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
starting anything — Claude Code and Copilot CLI run on every node
backend (the harness translates their wire to the node's), as does our own
loop; Codex CLI needs OpenAI's Responses API, which has no translator yet —
and refuses a foreign kind until its vendor CLI is installed on the node
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

Let the planner pick nodes when you only care that a model runs somewhere:
`noo cluster place-model <model>` prints `place <model> on <node> (<reason>)`
and needs `--apply` to act; `auto-place <model>...` plans a set across
the fleet; `reconcile-models` does the same for `NOO_DESIRED_MODELS` minus
what is already running.

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

`inference run` posts to `/api/inference` and prints the response;
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
| `noo cluster scale` | `<backend> -r\|--replicas <n> [-m\|--model <model>] [-y\|--yes]` | Scale a backend to N replicas fleet-wide; scale-down asks for confirmation (-y) |
| `noo cluster desired` | `<node>` | Show the desired config and every placement (with its role) the node-agent converges to |
| `noo cluster proposals` | `[--status <s>] [--limit <n>]` | List the enrolment proposals agents filed, with each host in full |
| `noo cluster show` | `<node>` | Show one node in full: hardware, agent version, tier drift, bus principal, roles |
| `noo cluster forget` | `<node> [--purge-tailscale] [-y\|--yes]` | Remove a dead node's row, KV entry and enrollments; --purge-tailscale drops its device |
| `noo cluster place` | `<node> <backend\|harness> <model\|auto> [--on cpu\|gpu] [--env KEY=VALUE]... [--kind noo\|claude-code\|copilot\|codex] [--role chat\|embed\|rerank] [--port <port>] [--tls] [--image <image>] [--stopped] [--force]` | Declare a backend and model in a role on a node, on cpu or gpu; auto-tunes unless --env |
| `noo cluster unplace` | `<node> <backend> [--role chat\|embed\|rerank]` | Remove a placement (one role); a container is left running, the harness is stopped |
| `noo cluster fit` | `<node> [--with <backend> <model> [--on cpu\|gpu] [--role <role>] [--env KEY=VALUE]...]` | Show whether placements fit a node's GPU memory and RAM, with or without one more |
| `noo cluster class list` | — | Show the model classes consumers may send as `model`, with candidate placement and health |
| `noo cluster class set` | `<class> <node>/<backend>[=<model>]... [--degraded <node>/<backend>[=<model>]]... [--alias <name>]...` | Declare a model class: candidates in failover order; --degraded ones answer last |
| `noo cluster class unset` | `<class>` | Forget a declared model class and its aliases; the derived class of its model takes over |
| `noo cluster logs` | `[<node>] [<service>] [-b\|--backend <backend>] [-n\|--tail <n>]` | Tail logs for a noo-* container or host service (harness, agent) on one node or all |
| `noo cluster restart-agent` | `<node>` | Ask the gateway to restart a node's node-agent |
| `noo cluster maintenance` | `<node> on --reason <text> [--until <duration>] \| <node> off \| list` | Mute a known-down node's operator alerts (operator-only); the daily summary still lists it |
| `noo cluster up` | `<backend> <model> [--node <node>] [--replicas <n>]` | Start a backend with a model via the imperative start route (prefer place) |
| `noo cluster init-secret` | — | Generate and print a fresh random cluster secret locally (no gateway call) |
| `noo cluster assign` | `<task> [--node <node>] [--backend <backend>] [--model <m>] [--priority low\|medium\|high\|<n>] [--dry-run] [--async]` | Pin a task to the least-loaded node and run it; --dry-run prints the choice only |
| `noo cluster set-config` | `<node> [--usage shared\|dedicated\|default] [--harness auto\|manual\|off] [--loop-budget <n>\|default] [--data-root <path>] [--models-dir <path>] [--ip <ip>] [--tier <n>] [--gpu-model <model>] [--vram-gb <n>] [--min-battery <pct>] [--require-wifi <bool>] [--block-thermal <s,s>] [--policy-default]` | Update a node's stored config row with only the given fields |
| `noo cluster clear-cooldowns` | — | Clear backend auto-start cooldown backoff on every node |
| `noo cluster add-companion` | `<node> [-p\|--platform <p>] [--hostname <host>] [--ip <ip>] [-s\|--sensors <a,b>] [-b\|--backends <a,b>] [--battery <n>] [-n\|--network <type>] [--npu-tops <n>] [--app-version <v>]` | Register a Tier-5 companion device with the gateway and send a first heartbeat |
| `noo cluster add-monitor` | `<node> [--hostname <host>] [--ip <ip>] [-s\|--services <a,b>]` | Register a Tier-6 monitor node with the gateway and send an initial heartbeat |
| `noo cluster teardown-node` | `<node> \| --all [--purge-data] [--purge-tailscale] [--factory] [-y\|--yes]` | Dismantle one node or --all via a signed teardown bundle, verify silence, then forget |
| `noo cluster provision` | `<node> [<tier>] [--harness auto\|manual\|off] [--wait [<secs>]] [--stage-only] [--move-data]` | Stage a node's signed bundle; --wait blocks until enrolled, --stage-only skips the apply |
| `noo cluster sync-model-files` | `[<node>...] [-m\|--model <file>]... [--dry-run]` | Dispatch a job per node to pull GGUF weights from the controller store and verify them |
| `noo cluster auto-place` | `<model>... [-b\|--backend <backend>] [--apply]` | Plan placement of a set of models across the fleet; --apply starts them |
| `noo cluster place-model` | `<model> [-b\|--backend <backend>] [--node <node>] [--apply]` | Pick the best node for a model by capability and cache; --apply starts it there |
| `noo cluster reconcile-models` | `[<model>...] [-b\|--backend <backend>] [--apply]` | Plan placement for desired models (args or NOO_DESIRED_MODELS) not yet running |
| `noo cluster mint-join-key` | `[--tag <tag>] [--expiry-minutes <n>] [--reusable]` | Mint a pre-authorized tagged Tailscale auth key (bootstrap-node lane is retired) |
| `noo cluster bootstrap-token create` | `[--ttl <1h\|30m\|24h\|secs>] [--role <role>] [--cidr <cidr>] [--node <name>] [--with-tailscale\|--no-tailscale]` | Mint a single-use enrollment token and print the node enrollment one-liner |
| `noo cluster bootstrap-token list` | — | List bootstrap tokens with status, creator, expiry and redeeming IP |
| `noo cluster bootstrap-token revoke` | `<id>` | Revoke a bootstrap token by id (idempotent) |
| `noo cluster bootstrap-token` | — | Print bootstrap-token subcommand usage (create, list, revoke) |
| `noo cluster set-primary` | `[--to <target>] --promoted [-y\|--yes]` | Move the primary-controller role; promote Postgres on the target first, then --promoted |
| `noo cluster sync-images` | `[<node>...] [-i\|--image <img>]... [--images <a,b>] [--restart\|--no-restart] [--all]` | Stage images on the artifact rail for each node's arch, then have its agent pull them |
| `noo cluster stage-images` | `[--lock] [-i\|--image <img>]... [--arch <a,b>] [--all-images]` | Pull images with the controller's login and stage them on the artifact rail per fleet arch |
| `noo cluster upgrade-agents` | `[<node>...] [-y\|--yes]` | Restage node agents serially in signed bundles over the pull rail; asks to confirm (-y) |
| `noo cluster upgrade-hostd` | `<node>... [--skip-build] [-y\|--yes\|--force]` | Roll noo-hostd to the named nodes over the pull rail as a signed bundle |
| `noo cluster upgrade-applier` | `<node>... [-y\|--yes\|--force]` | Ship the current noo-apply to nodes over the rail; asks for confirmation (-y) |
| `noo cluster restart-backends` | `<node> <noo-svc>... [-y\|--yes\|--force]` | Restart noo-* backend containers on a node via a rail-delivered bundle |
| `noo cluster host-telemetry apply` | `[<node>...] [--all] [--include-controller] [-y\|--yes]` | Switch off tailscaled's log upload on nodes over the pull rail, one at a time |
| `noo cluster host-telemetry` | — | Print host-telemetry subcommand usage (apply) |
| `noo cluster vendor stage` | `<kind> \| --all [--os linux\|macos] [--arch x86_64\|aarch64]` | Fetch a harness kind's vendor CLI (and runtime) on the controller, checked against its pin |
| `noo cluster vendor status` | — | List staged vendor CLIs and runtimes per platform, and which nodes need which |
| `noo cluster vendor` | — | Print vendor subcommand usage (stage, status) |
| `noo cluster push-secrets` | `[<node>...] [--dry-run] [--explain] [--gateway-container <name>] [--sops-file <path>] [-y\|--yes]` | Stage fleet-wide secrets from env.sops as a bundle each node collects |
| `noo cluster nats-users render` | `[--rotate] [--dry-run] [-y\|--yes]` | Mint per-principal NATS passwords from the gateway registry and render users.conf |
| `noo cluster nats-creds rotate` | `<node\|gateway\|worker>... [--mint-only] [--restart] [-y\|--yes]` | Rotate a bus credential: nodes deliver over the rail; gateway/worker re-render + recreate |
| `noo cluster import-model` | `<node> <name> [--place] [--role chat\|embed\|rerank] [-b\|--backend <backend>]` | Import a published GGUF + Modelfile from the controller store into a node's ollama |
| `noo cluster ship-model` | `<hf_id> <node> [--name <name>] [--quant <quant>] [--place] [-b\|--backend <backend>]` | Convert an HF model to GGUF and have a node import it; needs a source checkout |
| `noo cluster clean` | `<node>\|all [--deep] [-y\|--yes]` | Remove this stack's containers on node(s) through their agents; --deep removes images too |
| `noo cluster seed` | `[-f\|--file <path>] [--export] [--dry-run]` | Apply (or export) the cluster desired state from config/cluster-seed.yaml |

### `noo models` — Model catalog, search, pull, recommended
| Command | Arguments | What it does |
|---|---|---|
| `noo models cached` | — | List models currently loaded on running node backends |
| `noo models pull` | `<model> [--backend <b>]` | Pull a model onto the gateway's Ollama (not a chosen node) with streamed progress |
| `noo models fetch` | `<hf_repo> <file.gguf> [--revision <rev>] [--force]` | Download a GGUF from Hugging Face into the controller store (resumable, sha256-verified) |
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
| `noo inference run` | `<prompt> [-m <model>] [-b <backend>] [-n <node>] [-u <user>] [--max-tokens <n>] [-t <temperature>]` | Run one direct model inference through the gateway and print the response |
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
