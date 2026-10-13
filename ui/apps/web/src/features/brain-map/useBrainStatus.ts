// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useQuery } from '@metis/core';
import { apiGet } from '@/lib/client';

// Slate-harmonized dot colors.
const ON = '#5aa66e'; // green
const OFF = '#5b6472'; // grey / unknown
const WARN = '#e0a24a'; // amber
const BAD = '#c9524b'; // red
const GA = '#8a9a4e'; // olive

interface ClusterStatus {
  nodes?: { running_backends?: unknown[] }[];
}

/** Best-effort live status for the Brain Map dots. Anything unreachable stays
 *  grey (unknown).
 *
 *  The evolution lanes are the evolve add-on's. Core names none of its routes:
 *  the add-on ships its own route manifest and the gateway mounts it at
 *  runtime, so the dots for those lanes come from the add-on's state in
 *  `/health` (`enabled` lights them, `unhealthy` marks a fault) and the
 *  composite score is not shown here. The add-on's console piece is where a
 *  live score belongs; it can type its routes from its own manifest. */
export function useBrainStatus() {
  return useQuery({
    queryKey: ['brain', 'status'],
    refetchInterval: 15_000,
    queryFn: async () => {
      const [cluster, viol, health] = await Promise.all([
        apiGet<ClusterStatus>('/api/cluster/status'),
        apiGet<{ risk_level?: string }>('/api/security/violations'),
        apiGet<{ addons?: Record<string, string> }>('/health'),
      ]);
      const nodes = cluster?.nodes ?? [];
      const evolve = health?.addons?.evolve;
      const lane = (on: string) => (evolve === 'enabled' ? on : evolve === 'unhealthy' ? BAD : OFF);
      const dots: Record<string, string> = {
        'brain-sd-autonomy': nodes.length ? ON : OFF,
        'brain-sd-backend': nodes.some((n) => (n.running_backends ?? []).length > 0) ? ON : OFF,
        'brain-sd-security': !viol?.risk_level
          ? OFF
          : viol.risk_level === 'HIGH'
            ? BAD
            : viol.risk_level === 'MEDIUM'
              ? WARN
              : ON,
        'brain-sd-ga': lane(GA),
        'brain-sd-hofstadter': lane(WARN),
      };
      return { dots, score: null as number | null };
    },
  });
}
