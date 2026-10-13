// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery, useMetisClient } from '@metis/core';
import type { LayoutEdge } from '@/lib/graph/layout';

export interface GraphNode {
  id: string;
  name: string;
  type: string;
  degree: number;
}

export interface GraphData {
  nodeCount: number;
  edgeCount: number;
  maxDegree: number;
  types: { type: string; count: number }[];
  nodes: GraphNode[];
  edges: LayoutEdge[];
  /** True when the window hit `limit` — what's drawn is a slice, not the graph. */
  truncated: boolean;
}

export interface GraphFilters {
  limit: number;
  minDegree: number;
  entityType: string;
}

/**
 * Knowledge graph skeleton for the map, plus the type histogram.
 *
 * `/api/v1/graph/overview` returns edges as well as nodes; the panel used to
 * request it and keep only the node list, which is why there was never a map.
 */
export function useGraph(filters: GraphFilters) {
  const client = useMetisClient();
  return useQuery<GraphData>({
    queryKey: ['graph', filters.limit, filters.minDegree, filters.entityType],
    refetchInterval: 30_000,
    queryFn: async () => {
      const [s, o] = await Promise.all([
        client.GET('/api/v1/graph/stats'),
        client.GET('/api/v1/graph/overview', {
          params: {
            query: {
              limit: filters.limit,
              min_degree: filters.minDegree,
              ...(filters.entityType ? { entity_type: filters.entityType } : {}),
            },
          },
        }),
      ]);

      const types = Object.entries(s.data?.entity_types ?? {})
        .map(([type, count]) => ({ type, count: Number(count) }))
        .sort((a, b) => b.count - a.count);

      const nodes: GraphNode[] = (o.data?.nodes ?? []).map((n) => ({
        id: n.id || n.name || '?',
        name: n.name || n.id || '?',
        type: n.type ?? '',
        degree: n.degree ?? 0,
      }));

      const edges: LayoutEdge[] = (o.data?.edges ?? [])
        .filter((e) => e.src && e.dst)
        .map((e) => ({ src: e.src!, dst: e.dst!, relType: e.rel_type ?? '' }));

      return {
        nodeCount: o.data?.stats?.node_count ?? nodes.length,
        edgeCount: o.data?.stats?.edge_count ?? s.data?.total_edges ?? edges.length,
        maxDegree: o.data?.stats?.max_degree ?? Math.max(0, ...nodes.map((n) => n.degree)),
        types,
        nodes,
        edges,
        truncated: nodes.length >= filters.limit,
      };
    },
  });
}
