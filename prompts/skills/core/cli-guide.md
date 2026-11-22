---
name: cli-guide
version: "2.0"
description: "noomesh CLI + Dashboard guide — help users choose the right interface for the task"
author: noo-builtin
tags: [cli, terminal, commands, help, howto, dashboard, ui]
trigger_keywords: [cli, command, terminal, how to, command line, shell, bash, dashboard]
priority: 5
max_context_chars: 6000
composable: true
requires_tools: []
fitness: 0.0
generation: 0
parent_skill: null
---

# noomesh Interface Guide

Mesh has two interfaces: the **CLI** (`noo` commands in the terminal) and the
**Dashboard** (web UI). They talk to the same gateway — use whichever fits
the task. The gateway serves HTTPS only and binds loopback unless
`NOO_BIND_MODE` says otherwise: the dashboard is `https://localhost:8080` on
the controller, or `https://<controller>.<your-tailnet>.ts.net` from another
machine on the tailnet.

## How It Works: Controller vs Nodes

```
You (terminal or browser)
  │
  ▼
Controller (https :8080)    ← gateway, database, scheduler live here
  │
  ├──► Worker Node A (GPU)  ← runs AI backends (vLLM, Ollama, llamacpp)
  ├──► Worker Node B (GPU)
  └──► Worker Node C (CPU)
```

- The **CLI runs on any box it is installed on**: the controller, every enrolled
  node, or a laptop that talks to a remote controller. It sends instructions to
  the gateway. Verbs that act on the local stack (`noo stack`, `noo db`,
  `noo logs`, `noo security pki`) run only on the controller; a node refuses them.
- The **gateway routes work to worker nodes** — placements, model imports,
  jobs. Nodes pull their work; nothing logs into a worker.
- `noo models pull mistral` pulls into the **controller's own Ollama** (ollama
  only). To stage a model for a node: `noo models fetch ollama:<tag>`, then
  `noo cluster import-model <node> ollama:<tag>` (or `--place`).
- `noo cluster place <node> vllm <model>` declares vLLM on a **worker node**, not locally.
- Knowledge base, memory, and conversations live on the **controller** (PostgreSQL).

Set `CONTROLLER_URL` if the gateway isn't on localhost, or pass `--gateway` / `-G`.

## When to Use CLI vs Dashboard

| Task | CLI | Dashboard |
|------|-----|-----------|
| Quick commands, scripting, automation | **Best** | — |
| Chat with the AI | `noo chat` | Chat tab (richer: voice, history, feedback) |
| Check cluster health | `noo cluster status` / `verify` | Cluster tab (node cards with load bars) |
| Declare/remove backends | `noo cluster place` / `unplace` | Backends tab |
| GPU telemetry | — | **Observe tab (only here)** |
| Browse models & cache | `noo models search/cached` | Backends tab (cached models) |
| Ingest documents | `noo rag ingest file.pdf` | Documents tab (upload + URL input) |
| RAG query | `noo rag query "..."` | Explorer tab (full builds) |
| Explore knowledge graph | `noo graph search/detail` | Graph tab |
| Memory & embedding stats | `noo memory stats/embed` | Memory tab |
| Search conversations | `noo memory search "..."` | Memory tab |
| Job queue management | `noo jobs list/cancel/drain` | Jobs tab (full builds) |
| Approval queue | `noo approval list/approve` | Security tab (pending approvals) |
| Security violations | — | **Security tab (only here)** |
| Token usage | — | **Usage tab (only here)** |
| Architecture diagram | — | **Architecture tab (only here)** |
| Disk reclaim rule | — | Autonomy tab (rules) |
| Cron tasks | `noo heartbeat list/add` | — |
| Autonomy engine | `noo autonomy status/audit` | Autonomy tab (rules + decisions) |
| Multi-agent collab | `noo agents collaborate` | — |
| Workflows | `noo workflow run` | — |
| Voice | `noo voice transcribe/speak` | Chat tab (push-to-talk) |
| Prompt skills | `noo prompt-skills list/create` | — |
| Docker stack mgmt | `noo stack start/stop/rebuild` | — |
| Database migrations | `noo db upgrade head` | — |

**Rule of thumb:** CLI for operations and automation, Dashboard for monitoring
and visual exploration. Some things are CLI-only (mesh, heartbeat, workflows,
prompt-skills, db migrations). Some things are Dashboard-only (GPU telemetry,
security violations, token usage, the architecture diagram).

## CLI Quick Reference

### Talk to Your AI
```
noo chat                                  # Interactive conversation
noo inference run "prompt"                # One-shot (routed to best node)
noo inference run "prompt" -m mistral     # Specify model
noo inference agent "task"                # Agentic loop with tools
```

### Manage GPU Nodes (commands run on controller, affect worker nodes)
```
noo cluster status                        # All nodes, GPUs, backends
noo cluster provision <node>              # Provision an enrolled worker node
noo cluster place gpu-node-1 vllm Qwen/Qwen2.5-7B-Instruct  # Declare a backend + model (the agent converges)
noo --json cluster verify --wait          # Wait for the fleet; exit 0 = every check holds
noo cluster unplace gpu-node-1 vllm       # Remove the placement
noo cluster down vllm --node gpu-node-1   # Stop backend on a node now
noo cluster logs <node> [<service>] [-b <backend>] [-n <lines>]  # One-shot tail over the mesh (no -f)
```

### Models (staged on the controller, imported by nodes)
```
noo models search "mistral"               # Search HuggingFace
noo models pull <model>                   # Pull into the controller's Ollama (ollama only)
noo models fetch ollama:<tag>             # Stage an Ollama tag in the controller store
noo cluster import-model <node> ollama:<tag>  # Import it into that node's Ollama
noo models cached                         # Which models are on which nodes
noo models recommended                    # Models for your hardware tiers
```

### Knowledge Base (lives on controller in PostgreSQL)
```
noo rag ingest document.pdf               # Ingest a file
noo rag query "question"                  # Query with citations
noo rag status                            # Embedder health, counts
noo rag docs                              # List ingested documents
noo graph search "entity"                 # Search knowledge graph
noo graph detail <id>                     # Entity details + connections
noo graph neighbors <id> -H 2            # Traverse graph (1-3 hops)
```

### Memory (controller-side, PostgreSQL + pgvector)
```
noo memory stats                          # Storage & conversation stats
noo memory search "query"                 # Semantic search past chats
noo memory conversations                  # List recent conversations
noo memory tool-stats                     # Tool usage statistics
noo memory embed --watch                  # Process unembedded records
```

### Jobs & Scheduler (dispatched to worker nodes)
```
noo jobs list                             # Queue overview
noo jobs status <id>                      # Job details
noo jobs submit --type inference           # Submit a job
noo jobs cancel <id>                      # Cancel a job
noo jobs scheduler                        # Scheduler status
noo jobs pause / resume                   # Pause/resume dispatching
noo jobs drain <node>                     # Stop sending jobs to a node
```

### Approval Queue
```
noo approval list                         # Pending requests
noo approval approve <id>                 # Approve
noo approval deny <id> -r "reason"        # Deny with reason
```

### Automation & Self-Regulation
```
noo heartbeat list                        # Scheduled cron tasks
noo heartbeat add <name> <cron> --action daily_briefing
noo autonomy status                       # Self-healing engine status
noo autonomy audit                        # Recent autonomous decisions
```

### Multi-Agent & Workflows
```
noo agents collaborate "task"             # Roles via -r (default: researcher,analyst)
noo workflow list                         # Available pipelines
noo workflow run deep_research -i topic="X"
```

### Configuration
```
noo config show                           # Local YAML config
noo config get cluster                    # Runtime config from gateway
noo config set cluster '{"key":"val"}'    # Update runtime config
```

### Infrastructure (controller-only)
```
noo stack start / stop / rebuild          # Docker stack management
noo stack status / logs                   # Container health
noo db current                            # Migration status
noo db upgrade head                       # Run migrations
```

### Other
```
noo prompt-skills list / info / create    # Agent expertise templates
noo voice transcribe audio.wav            # Speech-to-text
noo channels status                       # Messaging adapter status
noo recall search "query"                 # Recall memory search
noo browser open "https://..."            # Browser automation
noo onboard                               # Setup wizard
noo --version                             # Version info
```

## Tips
- Add `--help` to any command: `noo jobs submit --help`
- Use `-v` / `--verbose` for detailed output
- Dashboard is at `https://localhost:8080` on the controller, or its tailnet
  `ts.net` name — same host and port as the gateway
- The dashboard is one page (`/`); Cluster, Documents, Observe, Security,
  Autonomy, Architecture etc. are tabs in its sidebar, not separate URLs
