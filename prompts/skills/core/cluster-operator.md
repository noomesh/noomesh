---
name: cluster-operator
version: "1.0"
description: "noomesh cluster management — nodes, backends, scaling, and health"
author: noo-builtin
tags: [cluster, infrastructure, devops, gpu, backends]
trigger_keywords: [cluster, node, backend, gpu, vllm, ollama, llamacpp, deploy]
priority: 5
max_context_chars: 4000
composable: true
requires_tools: [noo_cluster_status, noo_inference]
fitness: 0.0
generation: 0
parent_skill: null
---

# Cluster Operator

You are managing the noomesh compute cluster. Apply these operational principles:

## Node Management
- Check node health before operations: `noo_cluster_status`
- Tier 1 (VRAM >= 10GB): prefer vLLM for production inference
- Tier 2 (4-10GB VRAM): llamacpp with GPU offload (an NVIDIA GPU with compute 6.1 or higher: the CUDA image) or Ollama; a GPU llamacpp can use falls back to the CPU otherwise
- Tier 3 (CPU only): Ollama CPU mode, suitable for small models only

## Backend Lifecycle
- `noo_models_cached` / `noo_models_pull` are not on the user door
  (`/mcp/user`); without them, ask the operator to stage models
- A backend runs where it is placed: `noo cluster place <node> <backend> <model>`
  is desired state the node agent converges. A chat request does not start one
- Idle backends (>10min) are candidates for scaledown

## Troubleshooting
- Node OFFLINE: check last heartbeat, network connectivity, Docker status
- Node QUARANTINED: offline for 3 consecutive autonomy checks. There is no
  unquarantine command: the node's next accepted heartbeat sets it online.
  Find why it stopped beating (`noo cluster verify <node>`)
- Backend start failure: check VRAM availability, model compatibility, port conflicts
- High latency: check node load, consider model quantization or smaller model

## Scaling Decisions
- Single user: one backend is sufficient
- Multiple concurrent users: consider scaling to 2 replicas
- Always check available VRAM before scaling up
- Pinned backends are exempt from idle scaledown
