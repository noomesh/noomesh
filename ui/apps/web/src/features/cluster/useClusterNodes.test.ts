// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  get: vi.fn(),
  lastQuery: { current: null as null | Record<string, unknown> },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ GET: H.get }),
  useQuery: (opts: Record<string, unknown>) => {
    H.lastQuery.current = opts;
    return { data: undefined, isLoading: true };
  },
}));

import { useClusterNodes, type ClusterView } from './useClusterNodes';

beforeEach(() => H.get.mockReset());

async function run(nodes: unknown[]): Promise<ClusterView> {
  H.get.mockResolvedValue({ data: { nodes } });
  useClusterNodes();
  return (H.lastQuery.current!.queryFn as () => Promise<ClusterView>)();
}

describe('useClusterNodes — unreported is null, never 0', () => {
  it('a node with no tier has tier null, not 0', async () => {
    const d = await run([{ id: 'a', hostname: 'a' }]);
    expect(d.nodes[0]!.tier).toBeNull();
  });

  it('fleet VRAM is null if any node did not report its VRAM (no partial sum)', async () => {
    const d = await run([
      { id: 'a', hostname: 'a', vram_gb: 24 },
      { id: 'b', hostname: 'b' },
    ]);
    expect(d.stats.vramGb).toBeNull();
  });

  it('fleet VRAM sums when every node reported', async () => {
    const d = await run([
      { id: 'a', hostname: 'a', vram_gb: 24, tier: 1 },
      { id: 'b', hostname: 'b', vram_gb: 8 },
    ]);
    expect(d.stats.vramGb).toBe(32);
    expect(d.nodes[0]!.tier).toBe(1);
  });
});
