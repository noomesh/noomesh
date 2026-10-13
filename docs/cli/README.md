# The `noo` CLI

`noo` is a single static binary. Every command it serves is registered in
one table (`NATIVE` in `noo-cli/src/main.rs`) and described in one usage
table (`noo-cli/src/usage.rs`); a test pins the two 1:1, and
`scripts/gen-cli-docs.py` renders those same tables into the section pages
listed below. `noo --help` shows the sections; `noo <group> --help` lists a
group's commands; `noo <group> <command> --help` shows one command's
arguments.

## How it is organised

The six sections are the `GROUP_SECTIONS` the binary itself prints for
`noo --help`. Each group belongs to exactly one section, and each section
has a page here with its command reference.

<!-- BEGIN GENERATED: cli-sections — do not edit; regenerate with scripts/gen-cli-docs.py -->
| Section | Groups |
|---|---|
| [Setup & host](setup-and-host.md) | `whoami`, `onboard`, `enroll`, `offboard`, `upgrade`, `doctor`, `health`, `migrate`, `controller`, `bundle`, `systems`, `addons`, `kiosk`, `backups` |
| [Fleet](fleet.md) | `cluster`, `models`, `tools`, `inference`, `jobs`, `autonomy`, `skills`, `browser` |
| [Stack & data](stack-and-data.md) | `stack`, `db`, `logs`, `config`, `heartbeat`, `usage`, `plugins` |
| [Memory & knowledge](memory-and-knowledge.md) | `memory`, `rag`, `recall`, `graph`, `walks`, `ops`, `prompt-skills` |
| [Agents & channels](agents-and-channels.md) | `chat`, `agents`, `tasks`, `workflow`, `voice`, `channels`, `proactive`, `approval`, `mcp` |
| [Security](security.md) | `security`, `auth` |

**Setup & host** — [setup-and-host.md](setup-and-host.md)

- `noo whoami` — What this box is: controller, node, both, or client-only
- `noo onboard` — Setup wizard
- `noo enroll` — Join this machine to a noomesh fleet as a worker
- `noo offboard` — Leave the fleet: stop the agent, remove enrollment state (confirms)
- `noo upgrade` — Self-update the CLI; --stack/--nodes/--controller roll the rest
- `noo doctor` — Host-plane health checks with guided recovery
- `noo health` — Gateway health probe
- `noo migrate` — Move this controller to another device (export/import; NOT schema migrations)
- `noo controller` — Warm-standby failover: promote/demote via the stable role name
- `noo bundle` — Signed bundle inspection
- `noo systems` — Enable/disable optional systems (mints their secrets into sops)
- `noo addons` — Which add-ons this install runs — the `addons:` map, without opening the file
- `noo kiosk` — The unattended display's host seat: cage + Chromium showing /kiosk.html
- `noo backups` — Where backups go — and whether anyone has decided

**Fleet** — [fleet.md](fleet.md)

- `noo cluster` — Node management, provisioning (bootstrap-token + pull rail), teardown
- `noo models` — Model catalog, search, pull, recommended
- `noo tools` — Cluster tool registry
- `noo inference` — Run prompts on the GPU cluster
- `noo jobs` — Job queue & scheduler management
- `noo autonomy` — Autonomy engine monitoring & control
- `noo skills` — Containerized skill management
- `noo browser` — Browser automation

**Stack & data** — [stack-and-data.md](stack-and-data.md)

- `noo stack` — The Docker stack on THIS host: start/stop/restart/clean/status (the fleet is `cluster`)
- `noo db` — Schema migrations: mesh via the gateway's native runner, memory via alembic in trellion
- `noo logs` — Log aggregation
- `noo config` — Runtime configuration
- `noo heartbeat` — Cron scheduler for automated tasks
- `noo usage` — Token-usage summary
- `noo plugins` — Plugin management

**Memory & knowledge** — [memory-and-knowledge.md](memory-and-knowledge.md)

- `noo memory` — Memory & embedding management
- `noo rag` — PageIndex RAG commands
- `noo recall` — Episodic recall (System 1 memory)
- `noo graph` — Knowledge graph exploration
- `noo walks` — Your saved graph threads: recall them, and control saving
- `noo ops` — Asynchronous operations: long runs started as an op, polled for their result
- `noo prompt-skills` — Prompt skill templates

**Agents & channels** — [agents-and-channels.md](agents-and-channels.md)

- `noo chat` — Interactive chat with the cluster
- `noo agents` — Multi-agent collaboration
- `noo tasks` — Objectives the agent loops on until done
- `noo workflow` — Workflow automation
- `noo voice` — STT + TTS
- `noo channels` — Channel adapter management
- `noo proactive` — Proactive agent loop
- `noo approval` — Exec approval queue
- `noo mcp` — MCP server tools

**Security** — [security.md](security.md)

- `noo security` — Users, secrets, PKI, scanning, CA trust
- `noo auth` — Per-user CLI credentials
<!-- END GENERATED -->

## Reading a section page

Every section page has the same shape, top to bottom: **Covers / Does not
cover** (which groups live here and where the look-alikes went), a
**Disambiguation** paragraph when the section's group names collide with
each other or with another section, **Recipes** — the tasks an operator
actually does with these groups, in the order they do them, each with the
exact command and what success looks like — then the generated **Command
reference** (one table per group, straight from the binary's usage table),
and **Related guides** for the concepts behind the commands. Read the
recipes first; drop to the table when you need a flag; follow the guide
links when you need to know *why*.

## Which group do I want?

Names that collide in practice, one sentence each (taken from the group
taglines and the handler doc comments):

| If you want to… | Use | Not |
|---|---|---|
| Start, stop, restart, clean or inspect the Docker stack on **this host** | `noo stack` | `noo cluster` — that is the fleet: node management, provisioning (bootstrap-token + pull rail), teardown |
| **Move this controller to another device** (export/import of secrets, PKI, env, pg_dump) | `noo migrate` | `noo db upgrade` — that applies pending **schema** migrations (mesh via the gateway's native runner, memory via alembic in trellion) |
| Search or embed **conversation memory** (chat history, embedding stats and health) | `noo memory` | `noo recall` — episodic recall, the System 1 compressed recall-memory layer |
| Query or ingest **documents** in the PageIndex knowledge base | `noo rag` | `noo graph` — explores the knowledge graph (entities, edges, neighbours) extracted from those documents |
| Run a **containerized skill** (manifests under `skills/builtins/` and `~/.noo/skills`) | `noo skills` | `noo prompt-skills` — prompt skill **templates** served by the gateway |
| Add your own **command** to `noo` | `noo plugins` — an executable `noo-<name>` shim on `PATH` or in `~/.config/mesh/plugins/bin/`, git-style | `noo skills` / `noo prompt-skills` — those run inside the mesh, not in your shell |
| Set up **this machine** as a controller | `noo onboard` | `noo enroll` — joins this machine to an **existing** controller as a worker |
| Send one **prompt** and get an answer | `noo inference run` (one backend, no memory) or `noo inference agent` (the coordinator's tool loop) | `noo chat` — a streaming conversation that keeps its id across turns; `noo jobs run` — queued through the scheduler |
| Run one task through several **agent roles** | `noo agents collaborate` | `noo workflow run` — a named multi-step template; `noo agents send` — the agent-to-agent message bus |
| **Declare** that a node runs a backend with a model | `noo cluster place` (desired state; the node-agent converges) | `noo cluster up`/`down`/`scale` — the older imperative start/stop, forgotten on agent restart |
| Schedule something **recurring** | `noo heartbeat` (cron, user-facing tasks) | `noo autonomy` — condition → action self-healing patrols; `noo proactive` — rule-triggered notifications |
| Upgrade the **binary** or the **fleet's agents** | `noo upgrade` (`--stack`, `--nodes`) / `noo cluster upgrade-agents` | `noo stack rebuild` — rebuilds images from source on a checkout |
| Change a **security gate** (multi-user, exec approval, external MCP) | `noo security posture set` (DB allow-list, restart to apply) | `noo config set` — every other `noomesh.yaml` key |
| Rotate **certificates** | `noo security pki rotate-all` (leaves) / `pki rotate-ca` (the CA) | `pki push-nodes` — re-issue node certs and stage them on the pull rail when a node missed delivery |
| Fix a **database role** whose password drifted | `noo security secrets resync` (to the value already in the store) | `secrets rotate` — mints a new value; `noo cluster push-secrets` — fleet-wide keys to nodes |
| **Remove a node** | `noo cluster teardown-node` (live) / `noo cluster forget` (dead) | `noo cluster clean-node` — retired stub; `noo offboard` — tears down a **controller** |
| Decide a pending **tool call** | `noo approval` | `noo security user proposals` / `decide` — pending **account** proposals |

## Globals

Every native command accepts these (`print_native_help` in
`noo-cli/src/main.rs`):

| Flag | Meaning |
|---|---|
| `--json` | raw gateway JSON on stdout — for scripts and agents |
| `--quiet`, `-q` | captured values only (ids, secrets, paths) |
| `--color MODE` | `auto` \| `always` \| `never`; persist with `noo config set cli '{"color":"never"}'` |
| `--watch [S]`, `-w` | redraw a status command every S seconds (`stack status`, `cluster status`, `jobs list`) |
| `-G`, `--gateway URL` | target another gateway |
| `--instance NAME` | target a named instance (see [multi-instance](../getting-started/multi-instance.md)) |
| `--timeout S` | per-request timeout |
| `--token JWT` | explicit per-user credential |
| `-v`, `--verbose` | show requests and subprocess commands |

Two more native words are not commands in the registry and so do not appear
in the section tables: `noo --version` (`-V`) prints the binary's version,
and `noo completions <bash|zsh|fish>` emits a shell completion script that
asks the binary for candidates on every `<Tab>`, so an upgraded binary
changes what completion offers with no shell reload:

```sh
noo completions bash | sudo tee /etc/bash_completion.d/noo >/dev/null   # bash, system-wide
noo completions bash >> ~/.bash_completion                              # bash, this user
noo completions zsh  | sudo tee /usr/local/share/zsh/site-functions/_noo >/dev/null
noo completions fish > ~/.config/fish/completions/noo.fish
```

Environment the CLI reads (`noo-cli/src/envfile.rs`, `auth.rs`):

| Variable | Role |
|---|---|
| `CONTROLLER_URL`, `NOO_GATEWAY_URL` | gateway base URL when `--gateway` is not given (docker-internal `://gateway:` hosts are ignored); an enrolled worker falls back to `/etc/noo/controller-url`, then `http(s)://localhost:8080` plus the instance port offset |
| (stored credential) | `noo auth login` records the gateway that issued the credential, and the CLI sends it only there (or to loopback, the same box under another name). A `.env` that points the CLI elsewhere gets a 401, not your token — and not the refresh token either, because the check runs before the refresh |
| `NOO_TOKEN` | per-user credential, same as `--token` |
| `NOO_INSTANCE`, `NOO_PORT_OFFSET` | instance namespace and port offset (`--instance` sets the first) |
| `NOO_TLS_CERT` | when set, the default gateway URL is `https://` |
| `NOO_TLS_CA` | the CA the CLI verifies the gateway against. **Set-but-unusable is a hard error**, never a fall back to an unverified connection. Unset, the CLI uses the cluster CA at `$NOO_PKI_DIR/ca.crt` (default `~/.config/mesh/pki`) or `/etc/noo/pki/ca.crt`, else the platform verifier |
| `NOO_TLS_INSECURE` | **retired, and refused.** It existed briefly as an explicit opt-out of verification; setting it now is an error naming the fix, because an operator who sets it believes verification is off and must not be left believing that. There is no unverified-TLS lane to switch on — give the CLI an anchor instead (`$NOO_TLS_CA`, or `noo security trust-ca`) |
| `NOO_REPO_ROOT` | declares which checkout is this box's install. On an **enrolled** box the five transport variables above (plus `CONTROLLER_URL`, `NOO_TLS_KEY`) are only read from a declared root's `.env` / `noomesh.yaml` / `secrets/env.sops`, never from whichever checkout the cwd happens to be inside; an ignored file is named by `noo auth status` |
| `NOO_PAGER`, `PAGER` | pager for long listings (`less -R -F -X` by default when a person is watching; `PAGER=cat` disables) |
| `NO_COLOR`, `CLICOLOR_FORCE` | colour overrides, below `--color` and above the persisted preference |

## Contracts

These four rules hold for every native command. They are enforced in the files cited.

### Exit codes (`noo-cli/src/output.rs`, `enum ExitCode`)

| code | meaning |
|------|---------|
| 0 | success |
| 1 | generic / bad response (also a declined or missing destructive confirmation) |
| 2 | usage — unknown command or bad arguments |
| 3 | gateway unreachable |
| 4 | auth failed (401/403) |
| 5 | gateway returned an error status — including the explained 503 a disabled add-on's routes return, and `noo health` when the gateway is up but degraded |

Scripts branch on the code, not on prose.

### `--json` (`noo-cli/src/main.rs` module header, `output::fail`)

- `--json` prints the gateway's raw JSON on stdout, nothing else.
- Errors go to stderr — as `{"error","code","hint"}` JSON in `--json` mode.
- Narration is not stderr: a script that wants only the value passes
  `--quiet`. In default mode everything a person sees is stdout (header,
  results, steps, confirmations, guidance) so a redirect keeps it all;
  errors are stderr in every mode.
- `--watch` is a usage error (exit 2) under `--json`/`--quiet` or off a TTY.

### Destructive confirmation (`commands::confirm_destructive`, `noo-cli/src/commands/mod.rs`)

`stack clean`, `cluster down`, `cluster scale` (scale-down),
`security pki rotate-all`, `security untrust-ca`, `security team delete`,
`cluster teardown-node` and the other commands whose usage says
"asks for confirmation (-y)" share one gate:

- `--yes`/`-y` skips the prompt — this is the agent path.
- Without `--yes`, **stdin is a TTY**: print `{action} {target}? [y/N]:` on
  stderr, read one line, require `y`/`yes` (case-insensitive) to proceed;
  anything else prints `Aborted.` and exits 1.
- Without `--yes`, **stdin is not a TTY** (agent/pipe): do not block —
  print `confirmation required: pass --yes (…)` on stderr and exit 1.
- `--json` mode: never prompt; without `--yes` emit
  `{"error":"confirmation required: pass --yes","code":"confirmation_required",…}`
  on stderr and exit 1.

### Credential resolution (`noo-cli/src/auth.rs`)

1. `--token <t>` — explicit, wins over everything (scripts, CI, one-shots).
2. `NOO_TOKEN` — same, from the environment.
3. The stored per-user credential (`~/.config/mesh/credentials.json`,
   written by `noo auth login`), refreshed in place when the short-lived
   access token has expired and a refresh token is stored.
4. Nothing — requests go out unauthenticated and the gateway 401s, which
   the 401 message then explains (naming which credential it resolved and
   what to do about it).

There is no shared-secret rung. The CLI never signs a gateway request with
`NOO_CONTROLLER_SECRET` or `NOO_CLUSTER_SECRET`; `--break-glass` was removed
on 2026-10-03 and is refused by name (exit 2), and the gateway refuses any
HMAC a `noo` binary signs (an older binary is told to run
`noo upgrade --all`). Recovery is the ordinary path on the controller (lost password, lost operator certificate).

Access tokens live 15 minutes, the stored refresh 30 days; a 401 triggers
exactly one refresh-and-retry per process, a 403 never does.
`noo auth status` shows the whole resolution: which credential, which
gateway URL and which rung produced it, which TLS trust anchor, which config
root — plus any config file whose transport keys were ignored.

A gateway URL the CLI cannot verify is refused before the request is built
(exit 3, `tls_untrusted`): a non-loopback `http://` URL, or an `https://` one
with a `NOO_TLS_CA` that cannot be read or parsed. `http://` to a loopback
address is the one exception — the CLI's own default before TLS is configured.

## Related guides

- [../getting-started/install.md](../getting-started/install.md) — installing the binary
- `noo-cli/CLI_STYLE_GUIDE.md` in the repo — the output style
