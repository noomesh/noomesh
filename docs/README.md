# noomesh — Documentation Index

Every file under `docs/` is listed here exactly once
(`scripts/docs-check.py` enforces that). Read [getting-started](#getting-started)
first, then [cli](#cli) for how the command line is organised, then the
reference and operating pages as you need them.

## Placeholders in commands

Angle brackets mean "substitute your own value". The same idea always uses
the same placeholder, so a command copied from one page works on another:

| Placeholder | Means | Example |
|---|---|---|
| `<controller>` | the controller's address — its Tailscale MagicDNS name, or an IP | `noo-controller.your-tailnet.ts.net` |
| `<controller-ip>` | the controller's tailnet IP specifically, where a name will not do (`tailscale serve` binds an address) | `100.x.y.z` |
| `<node>` | a node's id or address | `worker-1` |
| `<your-tailnet>` | your tailnet name, shown only when spelling out the full MagicDNS form | `your-tailnet` in `noo-controller.your-tailnet.ts.net` |

`noo-controller` is the hostname the controller claims by default, not
something specific to any one install; `.ts.net` is Tailscale's suffix and
does not change. `tailscale status` prints your real names, and the CLI
reports the controller URL it resolved.

| Document | Description |
|----------|-------------|
| [../README.md](../README.md) | Project overview, quick start, architecture — the single entry point |

## Getting started

| Document | Description |
|----------|-------------|
| [getting-started/install.md](getting-started/install.md) | Install the `noo` binary, choose dev / dist / standalone, run `noo onboard`, `noo stack start`, and the `whoami` / `health` / `doctor docker` triage trio |
| [getting-started/troubleshooting.md](getting-started/troubleshooting.md) | The first-run failures: Docker and Compose, ports, the certificate warning, a model that is still loading, start-up refusals, a lost admin password |
| [getting-started/first-chat.md](getting-started/first-chat.md) | Your first conversation: `noo chat`, ask about the cluster, ingest one document with `noo rag`, the dashboard, and the two first-hour snags |
| [getting-started/add-ons.md](getting-started/add-ons.md) | What each add-on is, how to turn it on or off, what a disabled one returns, and where licensed ones are installed |
| [getting-started/standalone-controller.md](getting-started/standalone-controller.md) | A controller from the `noo` binary and Docker alone: the embedded deploy slice, `noo upgrade`, bundles, adding nodes |
| [getting-started/multi-instance.md](getting-started/multi-instance.md) | Several independent stacks on one host: `NOO_INSTANCE` + port offset, what they derive, the data-root and port guards |
| [getting-started/supported-hardware.md](getting-started/supported-hardware.md) | Tested and expected-to-work OS and hardware, what is not supported yet, node requirements, what fits where, the enrollment preflight, and a known Docker-repository issue on Pop!_OS |
| [getting-started/supported-agent-harnesses.md](getting-started/supported-agent-harnesses.md) | Which agent loops can run on a node (`noo`, `claude-code`, `copilot`, `codex`), which run today, the chat backends each can use, what happens when a kind cannot run, and where their telemetry switches are listed |
| [getting-started/trust-the-cluster-ca.md](getting-started/trust-the-cluster-ca.md) | Why the browser warns about the dashboard, the `ts.net` URL that needs no CA, and trusting the cluster CA in Chrome/Chromium, Firefox, macOS and Windows |
| [getting-started/kiosk.md](getting-started/kiosk.md) | Kiosk displays: `noo kiosk setup`, enrolling the display as a seat (never a node) with `noo kiosk seat-token` + `noo kiosk enroll`, and how `noo upgrade --all` keeps its CLI and kiosk assets current |

## CLI

One page per `noo --help` section; the command tables are generated from
the binary's own usage table by `scripts/gen-cli-docs.py`.

| Document | Description |
|----------|-------------|
| [cli/README.md](cli/README.md) | How the CLI is organised: sections, globals, exit codes, `--json`, destructive confirmation, credential resolution, and which group to use when names collide |
| [cli/setup-and-host.md](cli/setup-and-host.md) | `whoami` `onboard` `enroll` `node` `offboard` `upgrade` `doctor` `health` `migrate` `controller` `bundle` `systems` `addons` `kiosk` `backups` `tui` |
| [cli/fleet.md](cli/fleet.md) | `cluster` `models` `tools` `inference` `jobs` `autonomy` `skills` `browser` |
| [cli/stack-and-data.md](cli/stack-and-data.md) | `stack` `db` `logs` `config` `heartbeat` `usage` `test` `plugins` |
| [cli/memory-and-knowledge.md](cli/memory-and-knowledge.md) | `memory` `rag` `recall` `graph` `prompt-skills` `loop` |
| [cli/agents-and-channels.md](cli/agents-and-channels.md) | `chat` `agents` `tasks` `workflow` `voice` `channels` `proactive` `approval` `mcp` |
| [cli/security.md](cli/security.md) | `security` `auth` |

## Operating

| Document | Description |
|----------|-------------|
| [operating/operator-manual.md](operating/operator-manual.md) | The controller stack day to day: what runs where, `noo stack` start/stop/rebuild/reset, profiles and add-ons, upgrades, backups, troubleshooting |
| [operating/monitoring.md](operating/monitoring.md) | Prometheus scrapes, the gateway `/metrics` registry, node-agent and GPU exporters, alert rules, Grafana, Loki logs, health endpoints |
| [operating/token-budgets.md](operating/token-budgets.md) | Token budgets on tasks and allowances per person: the switch between loops, resubmitting or answering a parked task, and node vs cloud spend |

### Runbooks

| Document | Description |
|----------|-------------|
| [operating/runbooks/at-rest-recovery.md](operating/runbooks/at-rest-recovery.md) | The TPM-unlocked state volume (i10a): the volume does not open at boot, recovery over ssh with the recovery key, re-enrolling the TPM after a firmware or boot-chain change |
| [operating/runbooks/at-rest-migrate.md](operating/runbooks/at-rest-migrate.md) | Moving an existing controller's state onto the encrypted state volume (i10a): what migrate will and will not do, the steps, going back, and deleting the old plaintext |
| [operating/runbooks/backup-restore-secrets.md](operating/runbooks/backup-restore-secrets.md) | The two recovery artifacts, the restore drill, restoring a database or a whole controller, scheduled backups, passphrase rotation |
| [operating/runbooks/nats-isolation.md](operating/runbooks/nats-isolation.md) | Grant changes on the node's NATS credential: render and reload the bus before upgrading an agent that needs a new subject |
| [operating/runbooks/host-updates.md](operating/runbooks/host-updates.md) | Updating the OS without taking the mesh down: everyday vs platform packages, the hold command, canary → soak → controller, the pre-reboot check, and recovering a controller that does not boot |
| [operating/runbooks/security-release-upgrade.md](operating/runbooks/security-release-upgrade.md) | Taking an existing controller and fleet onto the posture-review release: the prerequisites that must precede the tag, the deploy, the posture, bus, agent and signing-key rollout after it, and a probe-by-probe verification checklist |

## Models

| Document | Description |
|----------|-------------|
| [models/weight-cache.md](models/weight-cache.md) | LAN model-weight cache: what the controller serves, how nodes preseed from it, `sync-model-files` and `model_cache_warm` |

## Channels

| Document | Description |
|----------|-------------|
| [channels/telegram.md](channels/telegram.md) | Telegram channel: one bot, one token, your user id |
| [channels/google-chat.md](channels/google-chat.md) | Google Chat channel: GCP project, service account, Pub/Sub, and what the wizard does with them |
| [channels/mcp-your-client.md](channels/mcp-your-client.md) | Connecting your own Claude Code (or any MCP client) to noomesh with a self-minted MCP key |

## Security

| Document | Description |
|----------|-------------|
| [security/node-agent.md](security/node-agent.md) | The node-agent trust contract: what the controller may make a node do and what it may not — declared host roots, the placement env allow-list, the container floor, MCP placements, and how a node reports a refusal |
| [security/networks-and-containers.md](security/networks-and-containers.md) | Which Docker network carries what, why Postgres and Redis answer on `noo-db` only, what the stunnel backend doors accept, and the container hardening the gateway and worker run under |
| [security/model-context.md](security/model-context.md) | What a model reads as instructions (operator-controlled text only) and what it reads as fenced, untrusted data (retrieved documents, memory, summaries, evolved skills, device reports) |
| [security/telemetry.md](security/telemetry.md) | No vendor telemetry: every component noomesh runs, what it would phone home with, the switch that stops it and how to verify it; and the outbound traffic that is not telemetry |
| [security/secrets.md](security/secrets.md) | The three configuration planes, the SOPS+age secret store, `noo security secrets audit / resync / rotate / absorb-files`, and backing up the age key |

## Development

| Document | Description |
|----------|-------------|
| [development/developer-guide.md](development/developer-guide.md) | Build, test and extend noomesh: repository layout, the toolchain per tree (cargo in Docker, go test, pytest), the test suite, and the extension points (MCP tools, skills, worker handlers, backends, CLI commands, routes) |
| [development/addons.md](development/addons.md) | Building an add-on: the declaration row, the route manifest the gateway proxies from, the drift check that belongs in your repo, and what presence/refusal/entitlement you get for free |
| [development/wsl-disk.md](development/wsl-disk.md) | Keeping a WSL2 controller's `.vhdx` from growing forever: log caps, rebuild pruning, the compact script |

## Reference

| Document | Description |
|----------|-------------|
| [reference/config.md](reference/config.md) | Every `noomesh.yaml` section and key, precedence, and where a value goes: secrets, config, posture, bootstrap flags, `compose_env`, behavioural flags |
| [reference/env.md](reference/env.md) | Every environment variable something actually reads, grouped by component: bootstrap, transport security, posture, gateway, node-agent, workers, compose |
| [reference/api.md](reference/api.md) | Every gateway route by area, the auth model, the WebSocket event format, and the two MCP doors |
| [reference/harness-protocol.md](reference/harness-protocol.md) | The contract between the gateway and any harness: bus subjects, the per-turn token, the `/api/harness/call` operation table, the events a harness publishes, and what a foreign runner must implement |

Outside `docs/`: `scripts/setup-dev.sh` prepares a Linux, WSL2 or macOS box
for development on this repo (toolchains, Docker, the venv, hooks and `noo`;
see the developer guide in the Development section). It is not an install
path; the "Getting started" section above is.
