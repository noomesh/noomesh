# Agents & channels

Covers: interactive chat with the cluster (`chat`), multi-agent collaboration (`agents`), workflow automation (`workflow`), STT + TTS (`voice`), channel adapter management (`channels`), the proactive agent loop (`proactive`), the exec approval queue (`approval`) and MCP server tools (`mcp`).

Does not cover: the cron scheduler (`noo heartbeat`, under Stack & data) or the autonomy engine (`noo autonomy`, under Fleet).

## Disambiguation

- `noo chat` is a **conversation**: a streaming REPL (or one turn with `--message`) where every turn shares one conversation id. `noo inference run` (Fleet) is one prompt to one backend with no memory; `noo inference agent` is one prompt through the coordinator's tool loop.
- `noo agents collaborate` runs one task through several **roles** in sequence; `noo agents send`/`inbox`/`thread` are the agent-to-agent **message bus**; `noo agents peer …` is the A2A door for **external** agents.
- `noo workflow run` executes a **named multi-step template** compiled into the gateway (`deep_research`, `code_development`, `data_analysis`) with per-step status.
- `noo channels` inspects and tests the inbound/outbound **adapters** (Telegram, Google Chat, WhatsApp); `noo proactive` is the rule-triggered notifier that sends through them; `noo heartbeat` (Stack & data) is the cron scheduler that can also deliver to them.
- `noo approval` is the queue of high-risk **tool calls** waiting for a human when the exec-approval posture is `approval`; `noo security user proposals` (Security) is the queue of **account** proposals.
- `noo mcp tools` lists what the local MCP door serves; `noo mcp external-setup` only prints the recipe for the external door and exits 2 — the credential itself comes from `noo security service-key` (Security).

## Recipes

### Talk to the cluster

```sh
noo chat
noo chat --model qwen2.5:7b-instruct --message "one line: what is a placement?"
```

The REPL probes `/health` first, then streams each turn over
`POST /api/inference/stream` (SSE); the banner says `gateway <url> ·
/exit or /quit ends the conversation`, the backend that answered shows on
stderr as `[vllm · qwen…]`. `--message` is one turn and returns; with
`--json` it prints `{"response","backend","conversation_id"}`. A pipe
without `--message` is refused (exit 2) rather than starting a REPL.

### Run a multi-role task or a workflow

```sh
noo agents list
noo agents collaborate "Design a backup plan for the KB" -r planner,reviewer
noo workflow list
noo workflow run deep_research -i topic="pgvector index tuning"
```

`collaborate` (300 s) prints each role's output under its own header and
ends `collaboration complete`; `-w` picks a named collaboration workflow,
`-m sequential` forces ordering. `workflow run` (600 s) prints `workflow
<name>   <ms>` then one line per step (`✓ <step>  done  <ms>` with the
step output beneath) and `workflow <name> completed in <ms>ms`; a failed
step exits 1. Inputs are `key=value` strings.

### Leave a message for an agent

```sh
noo agents send research-1 "pick up the KB backup thread" --kind task --thread kb-backup
noo agents inbox --agent research-1 --unread
noo agents thread kb-backup
noo agents messages --since 2026-09-01T00:00:00Z --threads
```

`send` publishes one envelope (`--kind message|task|result|ack|note`,
`*` broadcasts) and prints `sent <from> → <to>  thread <id>` plus the
message id; the gateway stamps your identity, node and harness on it.
Delivery is the NATS subscription; `inbox` and `thread` are reviews of
what the gateway recorded, newest first and oldest first respectively.
Non-privileged callers see only their own traffic. When the model reads
messages through its `noo_agent_inbox` / `noo_agent_thread` tools, the result
opens with a notice that the bodies are untrusted data written by others,
not instructions. External A2A agents
register themselves; `agents peer list -c` shows the connected ones,
`agents peer card` prints this gateway's own AgentCard, and `agents peer
dispatch <agent-id> "<task>"` fires a task and returns its id.

### Check the channels and send a test message

```sh
noo channels status
noo channels test telegram 123456789 -m "hello from noomesh"
```

`status` shows `channel | received | sent | errors`. `test` sends a
**real** message through the adapter (`whatsapp`, `telegram`,
`google_chat`) with no confirmation; a failed send prints `send failed:
<error>` and exits 1. To move channel identity between controllers:

```sh
noo channels export --output channels.json
noo channels import channels.json          # on the other controller
```

The export holds user links, team spaces and saved recipients. `import`
is idempotent; the users must already exist (`noo security user create`
first) because a link is an identity claim, while missing teams are
created. Set the channels up with
[telegram.md](../channels/telegram.md) and
[google-chat.md](../channels/google-chat.md).

### Decide a pending tool call

```sh
noo approval status                 # {"enabled","mode","timeout"}
noo approval list
noo approval approve <request-id>
noo approval deny <request-id> -r "not on a Friday"
```

Only **high-risk** tool calls queue, and only when the posture gate
`NOO_EXEC_APPROVAL_MODE` is `approval` (`auto` and `disabled` run
everything; any other value — including the unset default, `strict` —
denies high-risk calls outright). `noo onboard` applies the `hardened`
profile, which sets `approval`. The call
is held open for the approval window (300 s by default) and proceeds on
`approved <id> — the waiting tool call proceeds`; the deny reason is
shown to the agent. `stats` exits 5 rather than printing a silent zero
when the queue cannot be read. Set the gate with `noo security posture
set NOO_EXEC_APPROVAL_MODE approval` ([security.md](security.md)).

**Only a person decides.** `approve`, `deny` and the dashboard buttons use
your login; the gateway refuses a decision from the agent's own credential
(a tool call's delegated token), a harness or MCP-door key, a service
identity or an account that is not an enabled user, with a 403 that says
so. There is no approve or deny tool in the model's catalogue, so a model
cannot approve its own call. In a linked chat, the operator's reply
(`approve` / `deny`, or the card button) decides. A call with nobody
present (heartbeat, autonomy, a delegated child task) gets no special path:
`strict` refuses it at once, `approval` queues it for a decision by id and
refuses it when the window closes, and only an explicit `auto`/`disabled`
runs it.

Which calls are high-risk depends on what they do and where they point;
see [Tool risk tiers](../reference/config.md#tool-risk-tiers).

### See what the proactive loop is doing

```sh
noo proactive status
noo proactive rules
noo proactive history -n 50
```

Rules live in the `proactive.rules` section of `noomesh.yaml` (edit them
with `noo config set proactive …`); `status` shows how many are enabled,
`history` the recent firings with their channels and messages.

### Use the voice services

```sh
noo voice status
noo voice transcribe meeting.wav --language en --timestamps -o transcript.txt
noo voice synthesize "backup finished" -o done.wav
noo voice speak "backup finished"
noo voice voices
```

All five are thin calls to the gateway's `/api/voice/*` routes, which
proxy the whisper (STT) and piper (TTS) services that `addons.voice: true`
deploys — `status` reports what the **gateway** can reach, not what is
installed on your machine. `transcribe` allows 120 s (CPU whisper is
slow); `speak` plays through the first of `paplay`, `aplay`, `ffplay`,
`afplay` it finds.

### List the MCP tools and open the external door

```sh
noo mcp tools
noo mcp external-setup
```

`tools` speaks the MCP streamable-http handshake to the **operator** door
(`/mcp/operator` on the gateway) and prints `name | source | description`;
set `NOO_MCP_KEY` to your `mcp:operator` service key (`noo security
service-key issue <you>-mcp --scopes mcp:operator --user <admin>`). The
shared `NOO_MCP_TOKEN` is retired: it is never sent, and a leftover value
gets one line saying what replaces it. `external-setup` prints the recipe for `/mcp/user`
— open the posture gate (`noo security posture set
NOO_MCP_EXTERNAL_ENABLED 1`, restart), create the person's account, mint
them an `mcp`-scoped key, point the client at the door URL with a bearer
header — and exits 2, because the shared-token minter it replaced is
gone. The door refuses a key that is not bound to a user: bind one with
`noo security service-key issue <consumer> --scopes mcp --user <account>`,
or have the person log in and run `noo security service-key self`
([mcp-your-client.md](../channels/mcp-your-client.md)).

## Related guides

- [../channels/telegram.md](../channels/telegram.md) — Telegram channel setup
- [../channels/google-chat.md](../channels/google-chat.md) — Google Chat channel setup
- [../channels/mcp-your-client.md](../channels/mcp-your-client.md) — connecting your own MCP client with a self-minted key

## Recipes

*(filled in the next pass)*

## Command reference

<!-- BEGIN GENERATED: cli-reference section="Agents & channels" — do not edit; regenerate with scripts/gen-cli-docs.py -->
### `noo chat` — Interactive chat with the cluster
| Command | Arguments | What it does |
|---|---|---|
| `noo chat` | `[--model <m>] [--message <text>]` | Chat with the cluster gateway: streaming REPL, or one-shot with --message |

### `noo agents` — Multi-agent collaboration
| Command | Arguments | What it does |
|---|---|---|
| `noo agents list` | — | List agent roles with max tool loops and preferred tools |
| `noo agents peer list` | `[-c]` | List registered A2A peer agents; -c shows connected peers only |
| `noo agents peer card` | — | Print this gateway's public A2A AgentCard (/.well-known/agent.json) |
| `noo agents send` | `<to> <text…> [--from <agent>] [--agent <name>] [--harness <h>] [--thread <id>] [--kind message\|task\|result\|ack\|note] [--ref <msg-id>]… [--body <json>]` | Send a message to an agent, a thread, or * (broadcast; operator-only); recorded as you |
| `noo agents inbox` | `[--agent <id>] [--unread] [--limit <n>]` | Messages to --agent (any recipient if omitted), newest first; = messages --to |
| `noo agents thread` | `<thread-id>` | Every message in a thread, oldest first |
| `noo agents presence` | `[--owner <account>]` | Live MCP windows under an account, each by the name mail can address |
| `noo agents messages` | `[--agent <id>] [--from <id>] [--to <id>] [--user <u>] [--node <n>] [--harness <h>] [--kind <k>] [--since <rfc3339>] [--limit <n>] [--threads]` | Review agent traffic by agent, user, node or harness (operator); --threads lists threads |
| `noo agents collaborate` | `<task> [-r <roles-csv>]` | Run a multi-agent collaboration on a task and print each role's output (300s) |
| `noo agents peer dispatch` | `<agent-id> <task> [-r <role>]` | Dispatch a task to an A2A peer agent and print the task id |

### `noo tasks` — Objectives the agent loops on until done
| Command | Arguments | What it does |
|---|---|---|
| `noo tasks create` | `<objective> [--model <m>] [--budget <loops>] [-t\|--token-budget <tokens>]` | Give the agent an objective to loop on until done (needs `noo auth login`) |
| `noo tasks list` | `[--state <s>] [--user <u>] [-n <limit>]` | List tasks: yours, or everyone's as an operator |
| `noo tasks show` | `<id>` | One task: state, loops, last note, result |
| `noo tasks stop` | `<id> \| --via addon:<name> [--user <u>]` | Stop a task at its next checkpoint, or revoke an add-on's background work (--user: operators) |
| `noo tasks resubmit` | `<id> [-t\|--token-budget <tokens>]` | Give a task more tokens; one stopped out of tokens resumes from its checkpoint |
| `noo tasks answer` | `<id> <text>...` | Answer the question a task asked you; a new loop starts with your answer |

### `noo workflow` — Workflow automation
| Command | Arguments | What it does |
|---|---|---|
| `noo workflow list` | — | List available workflows with step counts |
| `noo workflow run` | `<name> [-i <key=value>]...` | Run a workflow synchronously and print per-step status (600s) |

### `noo voice` — STT + TTS
| Command | Arguments | What it does |
|---|---|---|
| `noo voice transcribe` | `<file> [--model <m>] [--language <l>] [-o <file>] [--timestamps]` | Transcribe an audio file through the gateway's whisper service |
| `noo voice synthesize` | `<text> [-o <file>] [--backend <b>] [--voice <v>] [--speed <s>]` | Synthesize speech via the gateway and write audio to a file (default speech.*) |
| `noo voice speak` | `<text> [--backend <b>] [--voice <v>] [--speed <s>]` | Synthesize speech via the gateway and play it with the first system player found |
| `noo voice status` | — | Report STT/TTS backend availability as seen by the gateway |
| `noo voice voices` | `[--backend <b>]` | List installed TTS voices, optionally filtered by backend |

### `noo channels` — Channel adapter management
| Command | Arguments | What it does |
|---|---|---|
| `noo channels status` | — | List configured channel adapters (traffic counters are not tracked) |
| `noo channels export` | `[--output <file>]` | Export user links, team spaces and saved recipients as portable JSON |
| `noo channels import` | `<file>` | Import channel state from an export file (idempotent; users must exist) |
| `noo channels test` | `<channel> <recipient> [-m <message>]` | Send a real test message through a channel adapter to a recipient |

### `noo proactive` — Proactive agent loop
| Command | Arguments | What it does |
|---|---|---|
| `noo proactive status` | — | Show proactive agent state and rule counts |
| `noo proactive rules` | — | List configured proactive rules |
| `noo proactive history` | `[-n <limit>]` | Say plainly that no firing history is stored (nothing records proactive firings) |

### `noo approval` — Exec approval queue
| Command | Arguments | What it does |
|---|---|---|
| `noo approval list` | — | List pending tool-execution approval requests |
| `noo approval pending` | — | Hidden: same as approval list |
| `noo approval stats` | — | Show approval-queue counts (total/approved/denied/pending/timed out/expired) |
| `noo approval status` | — | Show the exec-approval system status as JSON |
| `noo approval approve` | `<request-id>` | Approve a pending tool-execution request |
| `noo approval deny` | `<request-id> [-r\|--reason <reason>]` | Deny a pending tool-execution request |

### `noo mcp` — MCP server tools
| Command | Arguments | What it does |
|---|---|---|
| `noo mcp tools` | — | List the MCP hub's unified tool catalog via a streamable-http JSON-RPC exchange |
| `noo mcp external-setup` | `[-G <gateway-url>] [--save]` | Hidden: retired recipe printer for the external MCP door; exits 2 |
| `noo mcp server add` | `<id> --transport http --url <u> [--header K=$NAME]... [--kind tool\|device] [--audience a,b] [--note <t>] [--disabled]` | Register an http MCP server the node dials (record only; secrets as $NAME refs) |
| `noo mcp server list` | — | List registered external MCP servers with placement and tool counts |
| `noo mcp server show` | `<id>` | Show one external MCP server: spec, audience, placements, discovered tools |
| `noo mcp server enable` | `<id>` | Enable a registered external MCP server |
| `noo mcp server disable` | `<id>` | Disable a registered external MCP server without removing it |
| `noo mcp server remove` | `<id> [-y\|--yes]` | Remove an external MCP server record and its placements; confirms unless -y |
| `noo mcp place` | `<id> <node> [--stopped]` | Declare which registered node dials an external MCP server |
| `noo mcp unplace` | `<id> <node>` | Remove an external MCP server's placement from a node |
| `noo mcp import` | `[<file>] [--dry-run]` | Upsert external MCP servers and placements from a YAML data file |
| `noo mcp export` | `[-f\|--file <path>]` | Snapshot the external MCP server registry as an importable YAML data file |
<!-- END GENERATED -->
