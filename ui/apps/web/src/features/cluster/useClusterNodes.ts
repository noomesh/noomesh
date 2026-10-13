// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMetisClient } from '@metis/core';
import { relTime } from '@/lib/format';
import type { ClusterNode } from './types';

export interface ClusterView {
  nodes: ClusterNode[];
  stats: { total: number; online: number; busy: number; offline: number; vramGb: number };
}

/** Live cluster state from GET /api/cluster/nodes, polled every 15s (as legacy). */
export function useClusterNodes() {
  const client = useMetisClient();
  return useQuery<ClusterView>({
    queryKey: ['cluster', 'nodes'],
    refetchInterval: 15_000,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/cluster/nodes');
      if (error || !data) throw new Error('Cluster API unavailable');

      // A node with no identity is not a node. Without this an empty or
      // malformed entry renders as a card reading "(unknown) · ONLINE · 0
      // cores" — a machine that does not exist, in a view whose whole job is
      // telling you what you have.
      const rawNodes = (data.nodes ?? []).filter((n) => n.id || n.hostname);
      const nodes: ClusterNode[] = rawNodes.map((n) => ({
        id: n.id ?? '',
        hostname: n.hostname || n.id || '(unknown)',
        ip: n.ip || n.ip_address || '',
        tier: n.tier ?? 0,
        status: n.status ?? 'offline',
        gpu: n.gpu_model || undefined,
        vramTotal: n.vram_gb ?? undefined,
        cpuCores: n.cpu_cores ?? undefined,
        ramTotal: n.ram_gb ?? undefined,
        backends: n.backends ?? [],
        heartbeat: relTime(n.last_heartbeat),
      }));

      const vramGb = nodes.reduce((s, n) => s + (n.vramTotal ?? 0), 0);
      const stats = data.stats;
      return {
        nodes,
        stats: {
          total: stats?.total_nodes ?? nodes.length,
          online: stats?.online ?? nodes.filter((n) => n.status === 'online').length,
          busy: stats?.busy ?? nodes.filter((n) => n.status === 'busy').length,
          offline: stats?.offline ?? nodes.filter((n) => n.status === 'offline').length,
          vramGb,
        },
      };
    },
  });
}
