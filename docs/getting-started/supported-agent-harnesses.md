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
| `codex` | OpenAI's Codex CLI | Accepted, then **refused**: its wire is not served by any node backend yet | None yet (it speaks OpenAI's Responses API, which no node backend serves) | No switches declared yet, see [Telemetry](#telemetry) |

The kinds, the chat backends each can use, the vendor CLI each needs
(`cli`), how it is launched and its vendor telemetry switches are declared
once, in `config/harness-kinds.json`; the gateway and the node agent both
read that table.

There is ONE runner for every kind: the gateway binary in harness mode
(`noo-gateway harness`). For a foreign kind it launches the vendor's
headless CLI and fronts the node's model with a loopback wire translator, so
`runner` is `noo-gateway` for all four kinds and what differs per kind is
the vendor CLI that must be on the node. No noomesh image or installer ships
the Claude Code, Copilot or Codex CLI: install it on the node yourself. Until
you do, a placement of that kind is refused. `codex` stays refused by data:
its Responses API wire has no translator yet.

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

## What happens when a kind cannot run

The node agent checks a harness placement before it starts anything, in
this order, and reports the first problem as the placement's refusal:

1. **Wire compatibility.** The kind must speak the wire of the node's
   running chat backend. For example, `claude-code` on a node whose chat
   backend is vLLM is refused with the backends that would do; `codex`,
   whose wire no node backend serves yet, is refused saying so.
2. **Known kind.** Anything not in `config/harness-kinds.json` (`noo`,
   `claude-code`, `copilot`, `codex`) is refused.
3. **Runner shipped.** A kind with no runner in the table (none today) is
   refused with "its runner is not shipped yet".
4. **Runner installed.** Every kind's runner is `noo-gateway`; it is refused
   with "its runner ... is not installed on this node" when the binary is not
   where the node's installer puts it.
5. **Vendor CLI installed.** A foreign kind (`claude-code`, `copilot`) whose
   `cli` is not on the node's PATH is refused with "its runner is present
   but the \"claude\" command is not installed on this node".

So a placement tells you at once whether the kind would fit the node, even
before its runner exists. The node reports the refusal on its next
heartbeat ([../security/node-agent.md](../security/node-agent.md#when-a-node-refuses)),
and `noo cluster status` prints it as `<node> harness: <reason>`.

The gateway also refuses an unknown kind when you place it, before the node
is involved.

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

## Getting a harness added

A new kind is a change to `config/harness-kinds.json`, not a configuration
value: the gateway and the node agent are built with that table, so a node
or controller learns a new kind by upgrading. The row declares which chat
backends the kind can use, its vendor CLI (`cli`), its launch recipe and its vendor
telemetry switches (or that it has none); a test fails otherwise. To ask for
one, open an issue naming the harness and the wire it speaks.

See also [supported-hardware.md](supported-hardware.md) for the machines a
harness can run on.
