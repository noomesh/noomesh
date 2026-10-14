# noomesh

**Noomesh turns the machines you already own into one local-first AI
cluster.** A GPU workstation, a few Linux boxes, an edge board, a phone —
one self-managing assistant: multi-node inference,
knowledge-graph memory, scheduled and self-healing automation, and
messaging channels, all behind one gateway on your own network. No cloud
API is required; cloud models are an optional fallback.

Every operation is a plain `noo` command against the gateway, so the fleet
can be run by you at a terminal, by an AI agent driving the same commands,
or both — nothing is agent-only, and the controller holds the secrets, not
the intelligence.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](./LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)

[Quick start](#quick-start) • [Architecture](#architecture) • [Documentation](./docs/README.md) • [Contributing](./CONTRIBUTING.md)

## Quick start

One Linux box (or WSL2) with Docker and the compose plugin. An NVIDIA GPU is
optional. Full walkthrough:
[docs/getting-started/install.md](./docs/getting-started/install.md).

```bash
# 1. Install the noo CLI (static binary, checksum-verified, lands in ~/.local/bin)
curl -fsSL https://github.com/noomesh/noomesh/releases/latest/download/install.sh | sh
# 2. The wizard, run from any directory that is NOT a source checkout: it installs
#    into ~/.noo, pulls the released images, and walks prerequisites, secrets,
#    storage, the Docker stack, a first model, channels, add-ons
noo onboard
# 3. Day to day
noo stack start && noo health
```

When the wizard finishes: dashboard at `https://localhost:8080` (and on
your tailnet name, if you joined one). The certificate is issued by the
install's own CA, so a browser warns until it trusts that CA. Grafana at
`https://localhost:3000` comes up on every install (the monitoring set is in
both the `controller` and the `standalone` compose profile).
Then: [your first chat](./docs/getting-started/first-chat.md) ·
[add-ons](./docs/getting-started/add-ons.md) ·
[standalone controller](./docs/getting-started/standalone-controller.md).

Working on the code itself? Clone the repo and run `noo onboard` inside the
checkout — [install.md § Contributors](./docs/getting-started/install.md#contributors-run-from-a-checkout).

## Architecture

Three languages, each doing what it is best at, plus opt-in add-ons that
run as their own containers:

```
 channels (Telegram, WhatsApp, Google Chat)     web UI · noo CLI · MCP clients
                  │                                        │
                  ▼                                        ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  noo-gateway — Rust (gateway-rust/)                    :8080  │
   │  HTTP/WebSocket API, auth, coordinator loop, inference        │
   │  routing, job scheduler, heartbeat + autonomy loops,          │
   │  channels, both MCP doors (/mcp/operator, /mcp/user)        │
   └──────────────────────────────┬────────────────────────────────┘
                                  │ NATS (JetStream)
   ┌──────────────────────────────┴────────────────────────────────┐
   │  noo-worker — slim Python (src/noomesh/)           always on  │
   │  tool execution, non-ML services; handlers registered with    │
   │  @worker_handler · @tool · backend(...) · @capability         │
   ├───────────────────────────────────────────────────────────────┤
   │  noo-trellion — Python ML add-on (addons.trellion, on by def.)│
   │  RAG, memory search, knowledge graph, episodic recall         │
   │  noo-whisper / noo-piper — voice add-on (addons.voice, off)   │
   │  evolve / trellion-intel — licensed add-ons, separate repos   │
   └──────────────────────────────┬────────────────────────────────┘
                                  │ placement / desired state
   ┌──────────────────────────────┴────────────────────────────────┐
   │  noo-node-agent — Go (node-agent-go/), one per node    :8081  │
   │  hardware detection, heartbeats, starts/stops vLLM, Ollama,   │
   │  llama.cpp and embedding containers; companion sensors        │
   └───────────────────────────────────────────────────────────────┘

   Shared services: Postgres (pgvector) · Redis · NATS · sandbox (air-gapped
   executor) · model-cache · Prometheus/Grafana/Loki (monitoring profile)
```

- **Rust gateway** — the always-on front door. Owns the API surface and
  every deterministic loop; never blocks on Python.
- **Python worker** — the slim runtime that answers `worker.*` subjects on
  the bus. Each capability is a small registered unit
  (`src/noomesh/workers/registry.py`, `tools/decl.py`,
  `backends/__init__.py`, `pipeline/core.py`).
- **Add-ons** — the ML tree lives only in trellion, so the core image
  carries none of it; a disabled add-on's routes answer an explained 503
  and everything else keeps working ([add-ons](./docs/getting-started/add-ons.md)).
- **Go node agent** — per-node lifecycle: reconciles the gateway's desired
  state against the containers actually running on that hardware.


## What it does

- **Local inference** — Ollama, vLLM, llama.cpp; model-aware routing
  across nodes with automatic placement by tier
- **Fleet** — `noo cluster` enrolls, provisions and tears down nodes over
  a pull rail (nodes need only outbound HTTPS); desired-state placement,
  health monitoring, quarantine
- **Knowledge** — document ingestion, entity extraction, a temporal
  knowledge graph and graph-guided retrieval (trellion add-on)
- **Automation** — cron heartbeat tasks, watched folders, autonomy
  locations that self-heal, operator alerts
- **Channels** — Telegram, WhatsApp, Google Chat; MCP doors for your own
  Claude Code or any MCP client
- **Security by default** — JWT and per-user credentials, cluster HMAC,
  PKI/mTLS, secrets encrypted at rest with SOPS/age, sandboxed execution,
  audit logging

```bash
noo chat                         # talk to the cluster
noo cluster status               # nodes, tiers, running backends
noo cluster place <node> vllm <model>  # declare a GPU backend on a node
noo rag ingest <file>            # add a document to the knowledge base
noo heartbeat list               # scheduled tasks
noo --help                       # the six sections
```

## Configuration

One file, `noomesh.yaml` (start from
[`noomesh.yaml.example`](./noomesh.yaml.example)); secrets live in
`secrets/env.sops`; `.env` holds only a handful of bootstrap flags. Which
value goes where: [docs/reference/config.md](./docs/reference/config.md).

## Documentation

Start with [docs/README.md](./docs/README.md), the index of everything that
ships:

- [Install](./docs/getting-started/install.md) and
  [your first chat](./docs/getting-started/first-chat.md)
- [Troubleshooting](./docs/getting-started/troubleshooting.md) the first run
- [Add-ons](./docs/getting-started/add-ons.md), what each one is and how to enable it
- [CLI reference](./docs/cli/README.md), generated from the binary
- [Configuration](./docs/reference/config.md) and
  [environment variables](./docs/reference/env.md)
- [Telemetry](./docs/security/telemetry.md): there is none

## Contributing and security

[CONTRIBUTING.md](./CONTRIBUTING.md) covers setup, the worktree/PR flow
and tests. Report vulnerabilities per [SECURITY.md](./SECURITY.md).

## License

Noomesh core (gateway, CLI, node agent, console, compose files, docs) is
licensed under the **GNU AGPL-3.0-only** - see [LICENSE](./LICENSE).
Contributions are accepted under the [Contributor License Agreement](./CLA.md);
a bot asks first-time contributors to sign it on their pull request.

Trellion, the memory layer, is a separate repository,
[personifAI/trellion](https://github.com/personifAI/trellion), also AGPL-3.0-only.
A **commercial licence** for organisations that cannot take AGPL obligations is
available from PersonifAI LLC; its terms are in Trellion's
[COMMERCIAL-LICENSE.md](https://github.com/personifAI/trellion/blob/main/COMMERCIAL-LICENSE.md).
The licensed add-ons (trellion-intel, evolve) are proprietary and delivered
under the Intelligent-tier entitlement. See
[Add-ons](./docs/getting-started/add-ons.md#licensing-in-one-paragraph) for what
is free and what is licensed. The client SDK (`packages/noo-gateway-client`) is
Apache-2.0 so add-ons of any licence can use it.
Third-party attributions, including the Apache-2.0 Docker Hardened Images
Community bases, are in [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).

This is a summary, not legal advice; the licence texts govern.
