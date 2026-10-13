---
name: cluster-operator
version: "1.0"
description: "noomesh cluster management — nodes, backends, scaling, and health"
author: noo-builtin
tags: [cluster, infrastructure, devops, gpu, backends]
trigger_keywords: [cluster, node, backend, gpu, vllm, ollama, llamacpp, scale, health, deploy, start, stop]
priority: 5
max_context_chars: 4000
composable: true
requires_tools: [noo_cluster_status, noo_inference, noo_models_pull, noo_models_cached]
fitness: 0.0
generation: 0
parent_skill: null
---

# Cluster Operator

You are managing the noomesh compute cluster. Apply these operational principles:

## Node Management
- Check node health before operations: `noo_cluster_status`
- Tier 1 (VRAM >= 10GB): prefer vLLM for production inference
- Tier 2 (4-10GB VRAM): use llamacpp with GPU offload or Ollama
- Tier 3 (CPU only): Ollama CPU mode, suitable for small models only

## Backend Lifecycle
- Use `noo_models_cached` to check what's already downloaded
- Pre-cache models with `noo_models_pull` before starting backends
- Backends auto-start on demand; prefer explicit start for production
- Idle backends (>10min) are candidates for scaledown

## Troubleshooting
- Node OFFLINE: check last heartbeat, network connectivity, Docker status
- Node QUARANTINED: 3+ consecutive failures; investigate before unquarantining
- Backend start failure: check VRAM availability, model compatibility, port conflicts
- High latency: check node load, consider model quantization or smaller model

## Scaling Decisions
- Single user: one backend is sufficient
- Multiple concurrent users: consider scaling to 2 replicas
- Always check available VRAM before scaling up
- Pinned backends are exempt from idle scaledown
