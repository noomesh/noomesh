# Supported agent harnesses

For someone deciding what agent loop to run on a node. A **harness** is the
agent loop itself, placed on a node next to that node's chat backend, so a
turn runs beside the model instead of on the controller. This page says
which harnesses exist, which run today, which chat backends each can use,
and what each would send off the machine.

Not to be confused with connecting your own Claude Code (or any MCP client)
**to** noomesh: there, your client calls noomesh's tools through the MCP
door, and nothing is placed on a node. See
[../channels/mcp-your-client.md](../channels/mcp-your-client.md).

## At a glance

| Kind | What it is | Status | Chat backends it can use | Vendor telemetry |
|---|---|---|---|---|
| `noo` (default) | noomesh's own loop (`noo-gateway harness`) | **Runs today** | vLLM, llama.cpp, Ollama, AirLLM | None: no phone-home code |
| `claude-code` | Anthropic's Claude Code CLI | Runs once the vendor CLI (`claude`) is installed on the node | vLLM, llama.cpp, Ollama, AirLLM (the harness translates Anthropic's Messages API to the node's wire) | Switched off by a fixed set of variables, see [Telemetry](#telemetry) |
| `copilot` | GitHub's Copilot CLI | Runs once the vendor CLI (`copilot`) is installed on the node | vLLM, llama.cpp, Ollama, AirLLM (OpenAI's wire) | Offline mode only, see [Telemetry](#telemetry) |
| `codex` | OpenAI's Codex CLI | Runs once the vendor CLI (`codex`) is installed on the node | vLLM, llama.cpp, Ollama, AirLLM (the harness translates OpenAI's Responses API to the node's wire) | Switched off in the `config.toml` the harness writes for each run, see [Telemetry](#telemetry) |

The kinds, the chat backends each can use, the vendor CLI each needs
(`cli`), how it is launched and its vendor telemetry switches are declared
once, in `config/harness-kinds.json`; the gateway and the node agent both
read that table.

There is ONE runner for every kind: the gateway binary in harness mode
(`noo-gateway harness`). For a foreign kind it launches the vendor's
headless CLI and fronts the node's model with a loopback wire translator, so
`runner` is `noo-gateway` for all four kinds and what differs per kind is
the vendor CLI that must be on the node. The controller stages that CLI and
ships it to the node over the rail (next section); until the node has it, a
placement of that kind is refused.

## Vendor CLIs are staged by the controller

A node never fetches a vendor CLI. It gets one the way it gets the harness
binary itself: in its signed bundle, from the controller.

1. **Pin.** A kind's `distribution` in `config/harness-kinds.json` says
   where the vendor publishes the CLI (a URL template filled in from the
   node's platform), its version, and the sha256 each artefact must hash
   to. Changing a pin is a reviewed change to that file.
2. **Stage.** `noo cluster vendor stage` looks at the nodes and fetches,
   on the controller, every CLI a node's harness placement or
   `vendor_kinds` names, for that node's platform and no other. It refuses
   an artefact whose sha256 is not the pinned one, naming the URL and both
   digests and writing nothing, and ends by listing the
   `noo cluster provision <node>` commands that put the CLIs on the nodes.
   `noo cluster vendor stage <kind>` does the same for one kind;
   `--fleet` (with a kind) or `--all` (every kind) stages for every
   platform the fleet reports, needed or not, to have a CLI ready before a
   node names it. `--os` and `--arch` narrow any of these; both together
   name one platform outright.
   A CLI is 150–250 MB, so the fetch has no whole-download cap short of an
   hour: it reports how far it has got every 30 seconds and fails (then
   retries, four tries in all) only when no data arrives for 60 seconds.
   `noo cluster vendor status` lists what is staged and which nodes need
   which.
3. **Restage.** `noo cluster provision <node>` (or `noo upgrade --nodes`)
   puts the staged CLI in the bundle of every node whose
   harness placement names that kind, and of every node whose
   `vendor_kinds` lists it. `noo cluster vendor install <node> <kind>...`
   adds kinds to that list (`noo cluster set-config <node> --vendor-kinds
   <kind,kind>|none` sets it), so a node carries those CLIs whatever its
   placement names and can move between kinds without a restage. Each CLI
   rides in its own bundle slot, verified on its own. If one is not staged,
   the restage for that node is refused with the `noo cluster vendor stage`
   command to run: a restage never downloads.
4. **Placement.** The node's applier checks the sha256 again, unpacks the
   CLI under `/opt/noo/vendor/<cli>/<version>/` (`~/noomesh/vendor/` on a
   Mac) and writes a small wrapper named for the CLI at
   `/usr/local/bin/<cli>` (`~/noomesh/bin/<cli>` on a Mac), which is on the
   PATH of both the node agent and the harness. The agent's "vendor CLI
   installed" check passes, and the placement runs.

Installing a vendor CLI on a node by hand is no longer the path: the next
apply replaces a hand-installed command of the same name with the staged
wrapper. A kind with a `cli` and no `distribution` still runs from whatever
is on the node's PATH, until a pin lands for it.

The vendors' Linux builds are native executables linked against the
system C library (glibc), unlike the noomesh node binaries, which are
static: a node whose glibc is older than the vendor's floor fails when the
harness runs the CLI, and the harness reports the CLI's own error. A bundle
that carries a vendor CLI is large (each artefact is 100-250 MB), so the
first restage after a placement takes longer to stage and to fetch.

### The CLI runs jailed

The harness never runs a vendor CLI unconfined. On Linux the CLI runs in
a Landlock jail: it can write only its task's working directory, HOME and
TMPDIR, and read only the system trees a runtime needs, a short list of
`/etc` files and the cluster CA file. It cannot read the node's keys, env
files, secrets or data root, nor the harness's environment. The network is
not restricted. A node whose kernel cannot provide Landlock (or a Mac
without `sandbox-exec`) cannot run a foreign kind. Its tasks are
checkpointed with `harness jail unavailable: …; foreign CLIs never run
unjailed`, and the harness logs the reason at startup (`noo cluster logs
<node> harness`). The exact allow-list is in
[../security/node-agent.md](../security/node-agent.md#foreign-clis-run-in-a-jail).

## Place a harness

```sh
noo cluster place <node> harness auto                    # follow whichever chat backend the node runs
noo cluster place <node> harness auto --kind noo         # the same: that kind is the default
noo cluster set-config <node> --harness auto|manual|off  # follow the chat backend on its own
```

The full set of flags, the harness policy, loop budgets and the
`NOO_HARNESS_DISPATCH` brake are in
[../cli/fleet.md](../cli/fleet.md#place-the-harness).

The controller's own node takes a harness like any other node. The
controller box runs a node agent for its own node beside the controller
itself, and that agent is what starts the harness
([../security/node-agent.md](../security/node-agent.md)). A turn goes to
that harness only when one is placed there and the node's agent reports it
running. Without one, the controller runs the turn in process, as it
always has, and a task's `why` says which of the two is missing.

### Slow node models

A reasoning model on a slow node can spend several minutes on one model
call, mostly thinking (gemma4:12b on an M4 Mac mini took 3 to 4.5 minutes
per call). Three things keep such a turn from being lost:

- **Streams time out on silence, not on length.** A streamed answer has no
  total time limit; it is cut only when no byte arrives for
  `NOO_BACKEND_STREAM_IDLE_SECS` (default 300 s, which also covers the wait
  for the first token). A cut stream ends the turn with an error that says
  so, `the model stream was cut after Ns: <cause>`, and keeps whatever had
  already arrived. It is not treated as an empty answer, so the model is not
  nudged into another long call.
- **The turn stops at its deadline and saves first.** Your message is saved
  when the turn starts. The loop does not start another model call that
  cannot finish before `NOO_HARNESS_TURN_TIMEOUT_SECS` (default 900 s), and
  it ends a call still running at the deadline. It then saves the answer so
  far, or a note that the model did not finish, while the turn's credential
  is still valid.
- **A CLI that never reaches the model is killed early.** Every model call a
  vendor CLI makes passes through the harness's wire translator. A CLI that
  has made none for `NOO_HARNESS_STALL_SECS` (default 300 s; 120 s for a chat
  turn) is killed as stalled and the loop fails with `stalled: no model call
  for Ns`, instead of running to `NOO_HARNESS_TURN_TIMEOUT_SECS` loop after
  loop. A slow model is not a stall: a call in flight counts as activity.
  A chat turn whose CLI stalled before its first model call ran no tool, so
  the gateway runs that turn itself and the console gets an answer instead
  of an error.
- **Reasoning can be switched off per node.** Place the harness with
  `--env NOO_HARNESS_THINKING=off` and every model call on that node asks the
  model not to reason, for the `noo` loop and for a foreign kind's CLI
  alike. `on` forces reasoning; `auto`, the default, leaves it to the caller.
  The harness re-reads the placement every minute, so no restart is needed.

```sh
noo cluster place <node> harness auto --env NOO_HARNESS_THINKING=off
```

Both variables are described in
[../reference/env.md](../reference/env.md). Each node also gets defaults for
them from its harness profile, below.

## Harness profiles

Each node has a harness profile: six settings that decide how a harness
behaves on that node's hardware. The controller resolves it from three
sources and sends it to the node with the rest of its desired config:

1. a **per-node override**, which you set;
2. a **measured** value, from a bench of the node's chat model
   (`first_byte_secs` only);
3. the **tier default**, from the node's derived tier.

For each field the first source that has a value wins. The tier defaults
live in `config/harness-profiles.json`, which is built into the gateway and
the `noo` CLI. A node whose tier cannot be derived, or whose tier is not in
the table, gets the tier 3 row.

| Field | Tier 1 (controller-class CUDA) | Tier 2 (discrete GPU, Apple Silicon, Jetson) | Tier 3 (CPU worker) | Tier 4 (edge, SBC) | What it controls | Applied by |
|---|---|---|---|---|---|---|
| `first_byte_secs` | 290 | 600 | 900 | 900 | how long the node's inference proxy waits for a model's first byte (a cold load plus the prompt's prefill) | node agent, live, no restart |
| `stream_idle_secs` | 300 | 300 | 600 | 600 | how long a streamed answer may go silent before it counts as cut | harness |
| `thinking` | `auto` | `off` | `off` | `off` | whether model calls reason: `on`, `off`, or `auto` (the caller decides) | harness |
| `ollama_context` | 32768 | 32768 | 16384 | 8192 | the context length the node's ollama runs with when its placement sets no `OLLAMA_CONTEXT_LENGTH` | node agent |
| `claude_prompt` | `full` | `slim` | `slim` | `slim` | which Claude Code launch the harness uses: the full system prompt, or a slim one for small models | harness |
| `foreign_kinds` | claude-code, codex, copilot | claude-code, codex, copilot | codex, copilot | none | the foreign harness kinds this node may run (`noo` is always allowed); the agent refuses a placement of any other kind | node agent |

For the harness, the profile is a default and not a ceiling: a value in the
harness process env wins, then the harness placement's env
(`--env NOO_HARNESS_THINKING=off`), then the profile, then the built-in
default. For the node agent, the profile replaces
`NOO_BACKEND_FIRST_BYTE_TIMEOUT_SECS`, which still applies on a box whose
desired config carries no profile.

### See a node's profile

```sh
noo cluster profile <node>          # each field, its value and where it came from
noo cluster profile <node> --json   # the resolved profile as the node receives it
```

Each row names its source: `tier N`, `override (tier N: <default>)`, or
`measured from <model> at <time>`. The last block shows the node's bench, if
one has run, and whether it applies.

### Override a field

```sh
noo cluster profile <node> --set thinking=on
noo cluster profile <node> --set first_byte_secs=1200 stream_idle_secs=900
noo cluster profile <node> --set foreign_kinds=codex,copilot   # none: no foreign kind
noo cluster profile <node> --clear thinking                    # back to measured / tier
noo cluster profile <node> --clear-all
```

The gateway checks every value: `first_byte_secs` and `stream_idle_secs` are
whole seconds from 1 to 7200, `ollama_context` is whole tokens from 1 to
1048576, `thinking` is `on`, `off` or `auto`, `claude_prompt` is `full` or
`slim`, and `foreign_kinds` names foreign kinds from
`config/harness-kinds.json`. A value outside these rules is refused with the
reason, and nothing is written. Overrides are stored in the node's config
(`noo_node_config.harness_profile`) and reach the node on its next
desired-config poll.

### Bench the node's model

```sh
noo cluster profile <node> --bench
```

The controller asks the node agent to load the node's chat model and time a
reference prompt. The agent keeps the result and reports it on every
heartbeat as `model_bench`: load time, prefill and decode speed in tokens per
second, prompt size, and when it ran. The command prints those numbers and
then the re-resolved profile. A bench can take several minutes on a CPU
worker. The controller waits up to 900 s, and the agent stops at 600 s.

From a bench the controller works out a first-byte wait for a 30,000-token
prompt:

```
first_byte_secs = ceil((load_secs + 30000 / prefill_tps) × 1.5)
```

The result is never lower than the tier default and never higher than 1800
s. It applies only while the bench is of the model the node's chat placement
runs. After you place a different model, the bench is shown but not used
until you bench again. An override of `first_byte_secs` always wins over the
measured value. The other five fields are never measured.

If the bench cannot run, the command says why: the node has no chat backend,
a bench is already running, the chat backend failed, or the bench ran past
the agent's budget (then set `first_byte_secs` by hand).

The node's harness profile fills in what the env and the placement leave
unset. The gateway resolves it per node from the node's tier, a measured
model speed and per-node overrides (the noo CLI's cluster profile
command), and the
harness reads it from its node agent: `thinking` (after
`NOO_HARNESS_THINKING` in the harness's env and in the placement),
`stream_idle_secs` (after `NOO_BACKEND_STREAM_IDLE_SECS`; fixed when the
harness starts, so a change waits for a restart) and `claude_prompt`
(below; re-read every minute).

### Slim Claude Code for small models

Claude Code's own system prompt and its 20 built-in tool definitions make
its first request large. A small model must prefill all of it before its
first token. On an M4 Mac mini with gemma4:12b on Ollama, that first token
took longer than 290 s. With `claude_prompt=slim` in the node's profile
(the default for tiers 2 to 4), the harness runs the kind's `launch_slim`
instead of `launch`. The slim launch keeps every flag of the full one and
adds these:

- `--system-prompt-file`: a 550-character noomesh prompt replaces Claude
  Code's own. The prompt says what the run is, names the tools, and asks for
  the `NOO_RESULT:` / `NOO_FAILED:` line. The driver writes it into the
  task's HOME (mode 0600) and removes it after the run.
- `--tools Read,Write,Edit`: only the file tools, beside noomesh's MCP
  tools. No shell, no subagents, no web, no scheduling, no worktrees.
- `--disable-slash-commands`: no skills.

Measured against a recording mock model, Claude Code 2.1.292 sent this as
its first request, with no MCP servers:

| launch | tools | system prompt | request | about |
|---|---|---|---|---|
| full | 20 | 5,979 chars, plus 9,540 chars of context messages | 62,981 bytes | 15,700 tokens |
| slim | 3 | 686 chars, plus 1,124 chars of context messages | 5,597 bytes | 1,400 tokens |

The token figures are bytes divided by 4. noomesh's MCP tools are added to
both launches the same way.

To choose the launch for one node, set the override with
`noo cluster profile <node> --set claude_prompt=full` (or `slim`), and
`noo cluster profile <node> --clear claude_prompt` to go back to the tier
default. To compare the two launches on a node, pass
`--prompt full|slim` to the probe below.

## Probe a kind before placing it

`noo-gateway harness probe` runs a kind's real vendor CLI once per test,
exactly as the harness driver would run it for a task: the same launch
recipe, the same environment built from nothing (the kind's `lane` and
`telemetry_off` included), the same loopback wire translator, the same
process group, timeout and output caps. It does not mint a door key or
wire noomesh's MCP tools, and it never calls the gateway. Two tests:

- `reply`: the CLI is asked to answer `NOO_RESULT: ok`. It passes when the
  driver's verdict parser reads `ok`.
- `file`: the CLI is asked to create `probe.txt` containing `noomesh` and
  answer `NOO_RESULT: done`. It passes when the file is there with that
  content and the verdict is `done`. This shows that the model drives the
  CLI's own tool loop through the translator.

There are two modes:

- **Mock** (`--mock-model`): an in-process scripted model answers every
  call. It tests the wire and the flags, and needs no model and no root.
  For `file`, it calls whichever file-writing tool the CLI advertised and
  records that tool's name and argument keys in the report.
- **Real**: the node's own model. Settings come from `--model-url`,
  `--model` and `--backend`. Without those flags it reads
  `NOO_HARNESS_MODEL_URL`, `NOO_HARNESS_MODEL` and `NOO_HARNESS_BACKEND`.
  When `/etc/noo-harness.env` is readable, the probe fills in every
  variable that is not already set, the node certificate
  (`NOO_TLS_CA`, `NOO_TLS_CERT`, `NOO_TLS_KEY`) and the node-agent bearer
  included. The model calls then carry the same client identity the
  harness presents. That file is root-only, so the real mode runs with
  `sudo`. As root, the probe runs the CLI as `--run-as <user>` (default
  `nobody`) and refuses to run it as uid 0.

```sh
# mock: the wire and the flags, as yourself
noo-gateway harness probe --kind copilot --mock-model
noo-gateway harness probe --kind claude-code --cli /opt/claude/claude --mock-model --json
# real: the node's model, the CLI as an unprivileged user
sudo noo-gateway harness probe --kind codex --run-as nobody --json
```

Other flags: `--cli <absolute path>` (default: the kind's `cli` on PATH),
`--test reply|file|both` (default `both`), `--prompt full|slim` (Claude
Code's full or slim launch; default: the node's profile in real mode, else
full), `--context-tokens <n>` (the context window a CLI that takes one,
Claude Code or Codex, is told; default: the node agent's `model_context` in real
mode, else the CLI's own), `--timeout <secs>` (default 300), `--keep` (keep the workspace and print its path) and `--json`. For
each test the report gives the CLI version, PASS or FAIL with the first
concrete reason, the exit code, seconds, whether it timed out, every
translator route the CLI hit (method, path, status), token usage, and the
last 20 lines of stdout and stderr. The exit code is 0 only when every
selected test passed.

The probe changes no service, no placement and no file outside its
workspace under the system temp directory. It removes that workspace when
it finishes unless you pass `--keep`.

## What happens when a kind cannot run

The node agent checks a harness placement before it starts anything, in
this order, and reports the first problem as the placement's refusal:

1. **Wire compatibility.** The kind must speak the wire of the node's
   running chat backend. For example, `claude-code` on a node whose chat
   backend is vLLM is refused with the backends that would do. A kind whose
   wire no node backend serves (none today) is refused saying so.
2. **Known kind.** Anything not in `config/harness-kinds.json` (`noo`,
   `claude-code`, `copilot`, `codex`) is refused.
3. **Runner shipped.** A kind with no runner in the table (none today) is
   refused with "its runner is not shipped yet".
4. **Runner installed.** Every kind's runner is `noo-gateway`; it is refused
   with "its runner ... is not installed on this node" when the binary is not
   where the node's installer puts it.
5. **Vendor CLI installed.** A foreign kind (`claude-code`, `copilot`, `codex`) whose
   `cli` is not on the node's PATH is refused with "its runner is present
   but the \"claude\" command is not installed on this node". Stage it and
   restage the node (see above).

So a placement tells you at once whether the kind would fit the node, even
before its runner exists. The node reports the refusal on its next
heartbeat ([../security/node-agent.md](../security/node-agent.md#when-a-node-refuses)),
and `noo cluster status` prints it as `<node> harness: <reason>`.

The gateway also refuses an unknown kind when you place it, before the node
is involved.

## Compare kinds on a node

Which kind does better on your node is a measurement, not an opinion: the
eval harness in `eval/` runs the same task set under each kind, in turn, on
one node, and reports a row per kind. A scenario with a `harness_compare:`
block does it; `eval/scenarios/harness-compare-awolf.yaml` is the sample
(three tasks: a one-word reply, a question that needs a mesh tool, and a
two-step delegation, under `noo`, `copilot`, `claude-code` and `codex`).

**It changes the node's harness placement while it runs.** For each kind it
sets `NOO_HARNESS_KIND` on the node's `harness` placement (keeping the rest
of the placement's env), waits for the node to report the harness running
on a fresh heartbeat, then runs each task through `POST /api/tasks` and
polls it to the end. The original placement is put back at the end and when
the run fails; if the put-back itself fails, the report says so and gives
the command to restore the kind by hand. Run it when nobody else depends on
that node's harness. Placements and the tasks are the only things it writes.

From the repository root, with an operator credential in `NOO_EVAL_TOKEN`
(placing is an operator action) and the eval harness's Python dependencies
(`httpx`, `pydantic`, `pyyaml`):

```sh
PYTHONPATH=eval python3 -m noo_eval run eval/scenarios/harness-compare-awolf.yaml --gateway https://<controller>:8080
PYTHONPATH=eval python3 -m noo_eval run eval/scenarios/harness-compare-awolf.yaml --fixture
```

The second is a dry run against a built-in fake gateway: no cluster, no
writes, every number synthetic. It exists so CI can test the pipeline and
the report.

It writes `eval/reports/<scenario>.html` and a JSON twin beside it
(`.json`): per task set, one row per `harness_kind` with tasks passed out of
total, mean loops, mean wall seconds, prompt and completion tokens, and each
failure's first line; then every task run (state, loops, the node that ran
it, the check). A task the controller ran in process instead of the node's
harness fails by default (`require_dispatch`), because it measured the
controller and not the kind.

A task's `check` is one of `contains:<text>` (case-insensitive),
`regex:<pattern>`, `nonempty` or `state:<state>` (for example `state:done`).
A task with `kinds: [...]` runs only under those kinds.

Tokens come from `GET /api/usage/summary?group=backend`: the difference in
the `harness:<kind>` row before and after each task. Usage rows carry no
task id, so under an operator token the number is install-wide and counts
any other traffic of the same kind at the same time; set `task_token_env`
in the scenario to run the tasks as a user and read only that user's usage.
The `noo` kind records no token usage for its loops today, so its token
columns read "not reported" rather than 0.

## Telemetry

The vendor switches each third-party harness must be launched with, the
vendor documentation each comes from, and what the switches do not cover
(such as Claude Code's WebFetch hostname check) are in
[../security/telemetry.md](../security/telemetry.md#agent-harnesses). That
table is guarded by a test, so it stays the one place they are listed.

## Tested combinations

<!-- To fill in: the node / backend / model combinations the maintainers
run with a `noo` harness, in the same shape as the Tested table in
supported-hardware.md. Leave the foreign kinds out until a vendor CLI has been run on a node. -->

Not recorded yet.

## Which harnesses we support, and in what order

The foreign kinds we support, in priority order, are **Claude Code**,
**Codex** and **GitHub Copilot CLI**. They are the three in the table above,
and fixes, testing and documentation go to them first. A further kind is
considered only after these three have run on real node models.

An agent that is not a headless CLI is not a harness kind. Assistant-style
agents such as OpenClaw, Hermes Agent or Grok Build connect to noomesh as MCP
clients through the user door, wherever they run and on whatever model they
bring: see [../channels/mcp-your-client.md](../channels/mcp-your-client.md).
So does your own Claude Code, Codex or Copilot on a laptop.

A tool that improves an agent's prompts, tools and skills, rather than
running tasks, is not a harness kind either.

## Getting a harness added

A new kind is a change to `config/harness-kinds.json`, not a configuration
value: the gateway and the node agent are built with that table, so a node
or controller learns a new kind by upgrading. The row declares which chat
backends the kind can use, its vendor CLI (`cli`), its launch recipe and its vendor
telemetry switches (or that it has none); a test fails otherwise.

A candidate must be a headless CLI that runs from a prompt and exits, takes
a model endpoint we control, loads an MCP server from its configuration,
publishes versioned releases with checksums the controller can pin, and lets
its telemetry and update checks be switched off. It is offered once
`noo-gateway harness probe --kind <kind> --mock-model` passes inside the
jail, and recommended once it has passed against a real node model. To ask
for one, open an issue naming the harness and the wire it speaks.

See also [supported-hardware.md](supported-hardware.md) for the machines a
harness can run on.
