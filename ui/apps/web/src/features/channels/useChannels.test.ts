// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  get: vi.fn(),
  lastQuery: { current: null as null | Record<string, unknown> },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ GET: H.get }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
  useMutation: () => ({}),
  useQuery: (opts: Record<string, unknown>) => {
    H.lastQuery.current = opts;
    return { data: undefined, isLoading: true };
  },
}));

import { useChannels, type ChannelsData } from './useChannels';

beforeEach(() => H.get.mockReset());

async function run(status: unknown): Promise<ChannelsData> {
  H.get.mockImplementation((p: string) => Promise.resolve({ data: p === '/api/channels/status' ? status : {} }));
  useChannels();
  return (H.lastQuery.current!.queryFn as () => Promise<ChannelsData>)();
}

describe('useChannels — unreported is null, never 0', () => {
  it('stats: null + stats_detail yields null counters and carries the gateway detail', async () => {
    const d = await run({
      channels: { telegram: { stats: null, stats_detail: 'not tracked — counters do not exist' } },
    });
    expect(d.summary.activeConvos).toBeNull();
    expect(d.adapters[0]).toMatchObject({
      name: 'telegram',
      received: null,
      sent: null,
      errors: null,
      statsDetail: 'not tracked — counters do not exist',
    });
  });

  it('reported counters pass through, zero included', async () => {
    const d = await run({ active_conversations: 0, channels: { slack: { stats: { received: 0, sent: 3, errors: 0 } } } });
    expect(d.summary.activeConvos).toBe(0);
    expect(d.adapters[0]).toMatchObject({ received: 0, sent: 3, errors: 0, statsDetail: null });
  });
});
