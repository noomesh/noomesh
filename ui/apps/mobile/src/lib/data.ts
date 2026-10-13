// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMetisClient } from '@metis/core';

// Thin query hooks over the shared typed client. The companion re-implements just
// the few reads it needs (the web app's feature hooks stay web-side); the reused
// layer is the client + auth + query provider, not the UI.

export interface Node {
  id: string;
  hostname: string;
  status: string;
  gpu?: string;
  vram?: number;
  heartbeat: string;
}
export interface ClusterView {
  nodes: Node[];
  stats: { total: number; online: number; busy: number; vramGb: number };
}

export function useCluster() {
  const client = useMetisClient();
  return useQuery<ClusterView>({
    queryKey: ['cluster'],
    refetchInterval: 15_000,
    queryFn: async () => {
      const { data, error } = await client.GET('/api/cluster/nodes');
      if (error || !data) throw new Error('Cluster unavailable');
      const nodes: Node[] = (data.nodes ?? []).map((n) => ({
        id: n.id ?? '',
        hostname: n.hostname || n.id || '?',
        status: n.status ?? 'offline',
        gpu: n.gpu_model || undefined,
        vram: n.vram_gb ?? undefined,
        heartbeat: n.last_heartbeat ?? '',
      }));
      const s = data.stats;
      return {
        nodes,
        stats: {
          total: s?.total_nodes ?? nodes.length,
          online: s?.online ?? nodes.filter((n) => n.status === 'online').length,
          busy: s?.busy ?? nodes.filter((n) => n.status === 'busy').length,
          vramGb: nodes.reduce((a, n) => a + (n.vram ?? 0), 0),
        },
      };
    },
  });
}

export interface Proposal {
  id: string;
  host: string;
  user: string;
  role: string;
  status: string;
  reason: string;
}

export function useProposals() {
  const client = useMetisClient();
  return useQuery<Proposal[]>({
    queryKey: ['proposals'],
    refetchInterval: 20_000,
    queryFn: async () => {
      const res = await client.POST('/api/cluster/proposals', { body: { limit: 50 } });
      const status = res.response?.status;
      if (res.error || !res.data) {
        if (status === 403) throw new Error('Proposals require operator permission.');
        throw new Error('Proposals unavailable');
      }
      return (res.data.proposals ?? []).map((p) => ({
        id: p.id ?? '',
        host: p.host || '—',
        user: p.user_name || p.user || '—',
        role: p.role || '—',
        status: p.status ?? 'pending',
        reason: p.reason ?? '',
      }));
    },
  });
}
