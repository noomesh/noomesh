# Stack & data

Covers: the Docker stack on THIS host — start/stop/restart/clean/status (`stack`), schema migrations (`db`), log aggregation (`logs`), runtime configuration (`config`), the cron scheduler for automated tasks (`heartbeat`), token-usage summaries (`usage`), the test suite (`test`) and plugin management (`plugins`).

Does not cover: the fleet of nodes (`noo cluster`), or moving a controller between devices (`noo migrate` — `noo db upgrade` is schema migrations only).

## Disambiguation

- `noo stack` is the Docker stack on **this host** and talks to `docker` and the repo's `scripts/*.sh`, never to the gateway — so it keeps working when the gateway is broken. `noo cluster` (Fleet) is the **nodes**.
- `noo db upgrade` applies pending **schema** migrations (mesh via the gateway's native runner, memory via alembic inside trellion). `noo migrate` (Setup & host) exports and imports a whole **controller**.
- `noo config get`/`set` read and write the gateway's runtime config, which is `noomesh.yaml` on disk; `noo security posture set` (Security) is the separate allow-list of security gates in the database.
- `noo heartbeat` is the **cron** scheduler for user-facing tasks (briefings, reports, reindexes); `noo autonomy` (Fleet) is the self-healing engine; `noo proactive` (Agents & channels) is the rule-triggered notifier.
- `noo logs` reads container logs **through the gateway and node-agents** (and Loki, for `query`); `noo stack logs` reads `docker logs` on this host directly.
- `noo plugins list` finds executable `noo-<name>` shims on `PATH` (git-style); bare `noo plugins` prints its usage and exits 2. Nothing in `noo` hands off to a Python CLI: an unknown command or subcommand prints a usage error and exits 2, and Python-package plugins (`~/.noo/plugins`) are not served by this binary. `noo skills` (Fleet) runs sandboxed containers; `noo prompt-skills` (Memory & knowledge) are prompt templates.

## Recipes

### Start, watch and stop the stack

```sh
noo stack start                 # honours NOO_INSTALL_MODE: dev builds from source, dist runs released images
noo stack start --dist --tag stack-v0.2.2   # run a specific release (implies --pull)
noo stack status --watch 5
noo stack logs gateway --follow --tail 200
noo stack stop
```

`start` wraps `scripts/noomesh-start.sh`; `--dev` forces a one-off
source run, `--build` rebuilds first, `--profile <p>` adds a compose
profile (add-ons are not profiles you pass: the script reads the `addons:`
map in `noomesh.yaml` and composes each enabled add-on's overlay and
profile itself). `--dist` with `--dev` or `--build` is an error. `status`
is native `docker ps` — `service | state | since | image | ports` for
every `noo-*` container, `N of M containers not running` when something
is down, and `no containers` with a hint when nothing is. `logs` with one
service is `docker logs`; with none or several it is compose logs.
`stop --volumes` also removes the volumes. See
[the operator manual](../operating/operator-manual.md).

### Pick up changed env or secrets

```sh
noo stack restart --force gateway trellion
```

A plain `restart` keeps the **old** container environment, so a rotated
secret or a changed `compose_env` value never reaches the process;
`--force` recreates the containers (`up -d --force-recreate`) instead.
Name services to limit the blast radius; without names the whole stack
recreates.

### Rebuild images from source

```sh
noo stack rebuild                     # everything, in the foreground
noo stack rebuild gateway --quick     # one service
noo stack rebuild --background        # queue it for noo-hostd and get your terminal back
noo stack rebuild-status --follow
```

Foreground rebuilds run `scripts/noomesh-rebuild.sh` (`--no-cache`,
`--profile`, `--gateway-engine`/`--node-engine` are foreground-only).
`--background` needs noo-hostd running (the controller-mode user unit
`noo onboard` installs; `systemctl --user status noo-hostd`) — otherwise
it refuses and points at `noo onboard --only services` — and drops a
`stack-rebuild` job into `.noo-host-spool/` for hostd to run; the same
job shows in the dashboard under Self-Regulation → Host Operations.
`rebuild-status` prints `stack rebuild <status> at <ts> · rc <n>` and
the last lines of the log.

### Clean up, or start over

```sh
noo stack clean                  # containers, orphans, dangling images, build cache
noo stack clean --volumes -y     # also the volumes (keeps hf-cache, postgres and redis)
noo stack clean --deep -y        # everything: all images, data dirs, PKI and secrets
noo stack reset --dist           # deep clean → noo onboard → start from released images
```

`--volumes`, `--all` and `--deep` ask for confirmation (`-y` skips;
`--json` or a pipe refuses rather than blocks) and stop the self-heal
daemons first. `--deep` untrusts the old CA from the OS store before it
deletes the PKI dir, so a browser does not keep a stale root. `reset`
chains a deep clean, `noo onboard --skip-services` (`--ci` for the
non-interactive wizard, `--keep-env` to keep `.env`) and `noo stack
start`; on a TTY the script asks you to type `reset`.

### Check and apply schema migrations

```sh
noo db status         # local: gateway container health + every migration stamp (exit 1 if one is missing)
noo db current        # via the gateway: mesh / memory / evolve stamps, pending count
noo db history        # the mesh chain with applied/pending markers
noo db upgrade        # apply the pending mesh chain, then trellion's memory step
```

`upgrade` posts `/api/db/migrations/apply` (admin role) and prints `mesh
migrated <a> → <b>` or `mesh up to date at <rev>`, then execs trellion's
migration step (`memory migrated by noo-trellion`, `both chains at
head`). It applies the **whole** pending chain — `upgrade <rev>` for a
partial upgrade is refused (exit 2), exactly like the gateway does at
boot. `db stamp` is always refused: version stamps are owned by the
runners, and the command prints the manual `psql` recipe for when you
really mean it. `db verify-plane` runs `scripts/verify-privilege-plane.sh`
against a database and needs the checkout.

### Read and change runtime config

```sh
noo config show                        # the local noomesh.yaml as the file declares it
noo config get autonomy                # one section from the running gateway
noo config set autonomy '{"enabled": true}'
noo config export-effective -o effective.yaml
```

A section is any top-level key of `noomesh.yaml`; `set` deep-merges an
object into it, writes the **file** under a lock and refreshes the
gateway's cache, and audits the changed keys (never the values). Scalars
and arrays overwrite; an unknown section is created. `config set cli
'{"color":"never"}'` is local and persists CLI preferences. `export-
effective` is a best-effort snapshot of the runtime state — autonomy
locations, KB rules and grants — meant for reading, not for seeding.
See [config.md](../reference/config.md).

### Schedule a recurring task

```sh
noo heartbeat add "Weekly research" "0 8 * * 1" --action research_report --prompt "…" --channel telegram --recipient 123456789
noo heartbeat list
noo heartbeat run weekly_research        # now, synchronously; prints the result text
noo heartbeat history --task-id weekly_research
noo heartbeat toggle weekly_research --off
noo heartbeat set-schedule weekly_research "0 9 * * 1"   # move it; channels, recipients and config stay
noo heartbeat export --output tasks.json # and import <file> on another controller
```

The schedule is a **cron** expression (five fields; the gateway prepends
seconds) in the scheduler's timezone (`NOO_HEARTBEAT_TZ`, else the
`heartbeat.tz` key). The id is derived from the name
(`weekly_research`). Re-adding the same name replaces the whole task, so to
change only when it runs use `noo heartbeat set-schedule <task-id> "<cron>"`.
Actions come from `GET /api/heartbeat/actions` — `daily_briefing`,
`cluster_health`, `rag_reindex`, `memory_cleanup`, `idle_scaledown`,
`cert_auto_rotate`, `research_report`, `custom_prompt` (the default) and
others; some need the trellion-intel add-on, and `import` warns about
any task whose action is unavailable on this install. `run` prints
`task <id>: success (<ms>ms)` and the task's result text for quick native
actions; LLM or delegated actions answer `task <id>: queued — run <id>` and
finish in the background (`history --run <id>`). A task that deletes data,
written by an agent or the MCP door, is filed as a proposal instead:
`heartbeat proposals [<id>]` lists them and `approve` / `reject` decide them
at a terminal (people only). `remove` asks for confirmation.

### Find errors across the stack

```sh
noo logs errors -m 30                         # warnings and errors, every container, last 30 min
noo logs tail noo-ollama -n gpu-2 -l 200 --grep "CUDA"
noo logs containers
noo logs status                               # is Loki reachable? (only `query` needs it)
noo logs query '{container="noo-gateway"} |= "401"'
```

`errors`, `tail` and `containers` fan out to the node-agents over Docker
and work with Loki down; `-n` on `tail` is the **node**, `-l` the line
count. `tail --grep <regex>` filters the lines. `search [<text>]`
searches the fleet's logs in Loki by node, name, level and time window
(`--since`, `--until`); with Loki down it fails with the gateway's 503 and
has no scan fallback. `query` is raw LogQL against Loki. `noo usage -m 2026-08 -g model`
is the other read-only report here: token totals for a month (or
`--all-time`) grouped by `node|model|backend|source|user|consumer|day` (`-g`).

### Run the test suite (checkout only)

```sh
noo test run -k "test_auth" --no-failfast
noo test run --integration
noo test coverage --html
```

Spawns the repo's pytest (`$VIRTUAL_ENV`, else `venv/bin/python`) at the
checkout root; failfast is on by default and integration tests are
skipped unless `--integration`. See [testing.md](../development/developer-guide.md).

## Related guides

- [../operating/operator-manual.md](../operating/operator-manual.md) — what runs where, compose profiles, daily operations and troubleshooting
- [../reference/config.md](../reference/config.md) — every `noomesh.yaml` key
- [../reference/env.md](../reference/env.md) — every environment variable
- [../operating/monitoring.md](../operating/monitoring.md) — Prometheus, Grafana, health endpoints
- [../operating/monitoring.md](../operating/monitoring.md) — metrics, Grafana and the gateway `/metrics` endpoint
- [../development/developer-guide.md](../development/developer-guide.md) — project structure, conventions, running and writing tests

## Command reference

<!-- BEGIN GENERATED: cli-reference section="Stack & data" — do not edit; regenerate with scripts/gen-cli-docs.py -->
### `noo stack` — The Docker stack on THIS host: start/stop/restart/clean/status (the fleet is `cluster`)
| Command | Arguments | What it does |
|---|---|---|
| `noo stack status` | — | Show stack container status (from docker ps) |
| `noo stack logs` | `[<service>...] [--follow] [--tail <n>]` | Show container logs for one service or compose logs for many |
| `noo stack restart` | `[--profile <p>] [--force] [<service>...]` | Restart services by status name or add-on key; --force recreates (reloads env, secrets) |
| `noo stack start` | `[--profile <p>] [--pull] [--build] [--dist] [--dev] [--tag <tag>]` | Start the stack via scripts/noomesh-start.sh |
| `noo stack stop` | `[--volumes [-y\|--yes]]` | Stop the stack; --volumes deletes the database and every volume, after a typed confirm |
| `noo stack rebuild` | `[<service>...] [-q\|--quick] [--no-cache] [--profile <p>] [--gateway-engine <e>] [--node-engine <e>] [-b\|--background]` | Rebuild stack images in the foreground, or queue it for noo-hostd with --background |
| `noo stack rebuild-status` | `[--follow]` | Show the latest background stack-rebuild result and log |
| `noo stack clean` | `[--volumes] [--images] [--all] [--deep] [--cache] [--hf-cache] [-y]` | Remove Docker resources; asks for confirmation, -y answers every prompt too |
| `noo stack sync-assets` | — | Refresh the standalone deploy slice from this binary's embedded assets |
| `noo stack reset` | `[--dist] [--tag <tag>] [--ci] [--keep-env] [-y]` | Deep clean, onboard and restart the stack; destructive, confirms (-y) |
| `noo stack sandbox` | `<up [--fresh]\|status\|run <cmd>...\|rehearse\|down [--keep-data]>` | Manage a throwaway docker-in-docker Mesh stack isolated from live |
| `noo stack ollama` | `[--container <name>] [<ollama-args>...]` | Run an ollama command inside the noo-ollama container (default: list) |

### `noo db` — Schema migrations: mesh via the gateway's native runner, memory via alembic in trellion
| Command | Arguments | What it does |
|---|---|---|
| `noo db status` | — | Show gateway health and every migration stamp (mesh/trellion/evolve); --json supported |
| `noo db verify-plane` | `[<db>]` | Run scripts/verify-privilege-plane.sh against a database (default noo) |
| `noo db current` | — | Show the migration stamp of each system (mesh runner, trellion alembic, evolve) |
| `noo db history` | — | List the mesh runner's ported chain with applied/pending markers, plus other stamps |
| `noo db upgrade` | `[heads]` | Apply pending mesh migrations via the gateway, then trellion's memory step |

### `noo logs` — Log aggregation
| Command | Arguments | What it does |
|---|---|---|
| `noo logs errors` | `[-c\|--container <container>] [-m\|--minutes <min>] [-n\|--limit <limit>] [--node <id>] [--name <n>] [--source <s>] [--since <t>] [--until <t>]` | List recent warning/error lines across the fleet (Loki, else a container scan) |
| `noo logs tail` | `<container> \| -c\|--container <container> \| --name <n> [-l\|--lines <lines>] [-n\|--node <node>] [--source <s>] [--since <t>] [--until <t>] [--grep <regex>]` | Print the last N log lines of one container or unit, optionally on a given node |
| `noo logs search` | `[<text>] [-n\|--node <node>] [--name <n>] [-c\|--container <c>] [--source <s>] [--level <l>] [--since <t>] [--until <t>] [-l\|--limit <n>] [--newest] [-q\|--query <logql>]` | Search the fleet's logs in Loki by node, name, level, time window and text |
| `noo logs containers` | `[-n\|--node <node-id>]` | List Docker containers across cluster nodes via the node-agents |
| `noo logs query` | `<logql> [-l\|--limit <limit>]` | Run a raw LogQL query against Loki and print streams and lines |
| `noo logs status` | — | Report Loki connectivity and node-registry availability |

### `noo config` — Runtime configuration
| Command | Arguments | What it does |
|---|---|---|
| `noo config get` | `[<section>\|cli]` | Print gateway runtime config, whole or one section; `cli` reads this machine's prefs |
| `noo config set` | `<section> <updates-json>` | Update a gateway config section from JSON (no confirm); `cli` writes local prefs |
| `noo config launch-render` | `compose-env \| addons \| override \| systems [<file>]` | Hidden: render one noomesh.yaml section for the launcher scripts (internal) |
| `noo config launch-check` | `bind-sources [--data-root <dir>] [--no-deps] [--skip <service>]... [<service>...] \| system-credentials [<noomesh.yaml>] \| secrets-at-rest [<dir>] \| state-root [<dir>]` | Hidden: pre-start refusals: bind sources, credentials, plaintext secrets, closed volume |
| `noo config show` | `[--config <path>]` | Print noomesh.yaml: --config, $NOO_CONFIG, ./noomesh.yaml, ~/.config/mesh/config.yaml |
| `noo config export-effective` | `[-o <file>]` | Export the effective runtime config (autonomy + KB rules/grants) as YAML |

### `noo heartbeat` — Cron scheduler for automated tasks
| Command | Arguments | What it does |
|---|---|---|
| `noo heartbeat status` | — | Show heartbeat scheduler state, task counts and last tick age |
| `noo heartbeat list` | — | List configured heartbeat tasks with schedule, action and next run |
| `noo heartbeat run` | `<task-id>` | Run a heartbeat task now; quick tasks print their result, slow ones are queued to history |
| `noo heartbeat history` | `[<task-id>] [--task-id <id>] [--run <run-id>] [--limit <n>]` | Show recent heartbeat task runs, optionally filtered by task or a run id prefix |
| `noo heartbeat export` | `[--output <file>]` | Export all heartbeat tasks as portable JSON, stripping run timestamps |
| `noo heartbeat toggle` | `<task-id> [--on\|--off]` | Flip or explicitly set a heartbeat task's enabled state |
| `noo heartbeat set-schedule` | `<task-id> "<cron>"` | Change only a heartbeat task's schedule; channels, recipients and config stay as they are |
| `noo heartbeat proposals` | `[<proposal-id>]` | List task proposals; with an id, every field and a diff against the live task |
| `noo heartbeat review-existing` | — | After an upgrade: approve existing tasks and saved recipients one by one (people only) |
| `noo heartbeat approve` | `<proposal-id>` | Approve a task proposal at a terminal (shows it all; type the task id; people only) |
| `noo heartbeat reject` | `<proposal-id> [--reason <text>]` | Reject a task proposal; nothing is created or changed |
| `noo heartbeat add` | `<name> <schedule> [--action <a>] [--prompt <p>] [--channel <c>] [--recipient <r>]` | Add a scheduled heartbeat task with an id derived from its name |
| `noo heartbeat import` | `<file>` | Import heartbeat tasks from an export file and reload the scheduler |
| `noo heartbeat remove` | `<task-id> [-y]` | Delete a heartbeat task; destructive, asks for confirmation (-y) |

### `noo usage` — Token-usage summary
| Command | Arguments | What it does |
|---|---|---|
| `noo usage` | `[-m <YYYY-MM> \| --all-time] [-g node\|model\|backend\|source\|user\|consumer\|day]` | Show token-usage totals for a month or all time, grouped by a dimension |
| `noo usage me` | `[-p\|--period day\|week\|month] [-u\|--user <user>]` | Show your token spend this period: node, cloud and harness apart, and your allowance |

### `noo plugins` — Plugin management
| Command | Arguments | What it does |
|---|---|---|
| `noo plugins list` | — | List executable noo-<name> shim plugins found on PATH and in the plugins dir |
<!-- END GENERATED -->
