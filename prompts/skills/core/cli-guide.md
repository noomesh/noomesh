---
name: cli-guide
version: "2.0"
description: "noomesh CLI + Dashboard guide — help users choose the right interface for the task"
author: noo-builtin
tags: [cli, terminal, commands, help, howto, dashboard, ui]
trigger_keywords: [cli, command, terminal, how to, noo, command line, shell, bash, dashboard, ui, web]
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
**Dashboard** (web UI at `http://<controller>:8080`). They talk to the same
gateway — use whichever fits the task.

## How It Works: Controller vs Nodes

```
You (terminal or browser)
  │
  ▼
Controller (:8080)          ← gateway, database, scheduler live here
  │
  ├──► Worker Node A (GPU)  ← runs AI backends (vLLM, Ollama, llamacpp)
  ├──► Worker Node B (GPU)
  └──► Worker Node C (CPU)
```

- The **CLI always runs on the controller**. It sends instructions to the gateway.
- The **gateway routes work to worker nodes** — starting backends, pulling models,
  dispatching jobs. You never need to SSH into workers.
- `noo models pull mistral` downloads to a **worker node**, not the controller.
- `noo cluster up vllm` starts vLLM on a **worker node**, not locally.
- Knowledge base, memory, and conversations live on the **controller** (PostgreSQL).

Set `CONTROLLER_URL` if the gateway isn't on localhost, or pass `--gateway` / `-G`.

## When to Use CLI vs Dashboard

| Task | CLI | Dashboard |
|------|-----|-----------|
| Quick commands, scripting, automation | **Best** | — |
| Chat with the AI | `noo chat` | Chat tab (richer: voice, history, feedback) |
| Check cluster health | `noo cluster status` | Cluster tab (node cards with load bars) |
| Start/stop backends | `noo cluster up/down` | Backends tab (dropdowns, one-click) |
| GPU metrics & charts | — | **Observability tab (only here)** |
| Browse models & cache | `noo models search/pull` | Backends tab (HF catalog dropdowns) |
| Ingest documents | `noo rag ingest file.pdf` | RAG tab (drag-and-drop + URL input) |
| RAG query | `noo rag query "..."` | Explorer tab |
| Explore knowledge graph | `noo graph search/detail` | **RAG tab 3D graph (only here)** |
| Memory & embedding stats | `noo memory stats/embed` | Memory tab (richer: health score, charts) |
| Search conversations | `noo memory search "..."` | Memory tab (semantic search) |
| Job queue management | `noo jobs list/cancel/drain` | Jobs tab (same features, visual) |
| Approval queue | `noo approval list/approve` | Self-Regulation tab + Security page |
| Security violations | — | **Security dashboard (only here)** |
| Self-identity | — | **Self-Regulation tab (only here)** |
| Architecture diagrams | — | **Brain + Workflow pages (only here)** |
| Feedback & DPO export | — | **Feedback tab (only here)** |
| Disk cleanup | — | **Security dashboard (only here)** |
| Cron tasks | `noo heartbeat list/add` | — |
| Autonomy engine | `noo autonomy status/audit` | Self-Regulation tab |
| Multi-agent collab | `noo agents collaborate` | — |
| Workflows | `noo workflow run` | — |
| Voice | `noo voice transcribe/speak` | Chat tab (push-to-talk) |
| Prompt skills | `noo prompt-skills list/create` | — |
| Docker stack mgmt | `noo stack start/stop/rebuild` | — |
| Database migrations | `noo db upgrade head` | — |

**Rule of thumb:** CLI for operations and automation, Dashboard for monitoring
and visual exploration. Some things are CLI-only (mesh, heartbeat, workflows,
prompt-skills, db migrations). Some things are Dashboard-only (GPU charts,
3D graph, security dashboard, self-regulation controls, feedback/DPO).

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
noo cluster up vllm                       # Start backend (gateway picks node)
noo cluster up vllm --node gpu-node-1          # Start on specific node
noo cluster down vllm --node gpu-node-1        # Stop backend on a node
noo cluster scale vllm --replicas 3       # Run across 3 nodes
noo cluster logs <node>                   # Fetch node logs via SSH
```

### Models (downloaded TO worker nodes, not the controller)
```
noo models search "mistral"               # Search HuggingFace
noo models pull <model> --backend vllm    # Download to a worker node
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
noo agents collaborate "task"             # Planner + coder + reviewer
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
- Dashboard is at `http://<controller>:8080` — same host as the gateway
- Dashboard pages: `/` (main), `/brain` (architecture), `/workflow` (data flow),
  `/security` (violations & cleanup)
