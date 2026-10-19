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
2. **Stage.** `noo cluster vendor stage <kind>` (or `--all`) fetches every
   artefact the fleet's platforms need, on the controller, and refuses one
   whose sha256 is not the pinned one, naming the URL and both digests and
   writing nothing. `--os` and `--arch` narrow it to one platform.
   `noo cluster vendor status` lists what is staged and which nodes need
   which.
3. **Restage.** `noo cluster provision <node>` (or `noo upgrade --nodes`)
   puts the staged CLI in the bundle of every node whose
   harness placement names that kind. If it is not staged, the restage for
   that node is refused with the `noo cluster vendor stage` command to run:
   a restage never downloads.
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
`--test reply|file|both` (default `both`), `--timeout <secs>` (default
300), `--keep` (keep the workspace and print its path) and `--json`. For
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
two-step delegation, under `noo`, `copilot` and `claude-code`).

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
