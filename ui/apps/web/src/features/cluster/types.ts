// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import type { GpuContention } from './gpuContention';

// View model for a cluster node — the fields the NodeCard renders. Populated
// from the contract's node object (see mapNode). The optional telemetry fields
// (vramUsed/cpuPct/load) aren't in the current OpenAPI schema; they're kept
// optional so the card lights them up automatically once the contract adds them.
export interface ClusterNode {
  id: string;
  hostname: string;
  ip: string;
  tier: number;
  status: string;
  gpu?: string;
  vramTotal?: number;
  cpuCores?: number;
  ramTotal?: number;
  backends?: string[];
  heartbeat: string;
  // not yet in contract:
  vramUsed?: number;
  cpuPct?: number;
  ramUsed?: number;
  load?: number;
  // node agent `gpu_contention` (shared-GPU yield); absent from older agents
  gpuContention?: GpuContention;
}
