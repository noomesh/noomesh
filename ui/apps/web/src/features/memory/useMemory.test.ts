// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  get: vi.fn(),
  lastQuery: { current: null as null | Record<string, unknown> },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ GET: H.get, POST: vi.fn() }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
  useMutation: () => ({}),
  useQuery: (opts: Record<string, unknown>) => {
    H.lastQuery.current = opts;
    return { data: undefined, isLoading: true };
  },
}));

import { useMemory, type MemoryData } from './useMemory';

async function run(bodies: Record<string, unknown>): Promise<MemoryData> {
  H.get.mockImplementation((path: string) => Promise.resolve({ data: bodies[path] ?? {} }));
  useMemory();
  return (H.lastQuery.current!.queryFn as () => Promise<MemoryData>)();
}

beforeEach(() => H.get.mockReset());

describe('useMemory — unreported is null, never 0', () => {
  it('a payload with every count missing yields null throughout', async () => {
    const d = await run({ '/api/conversations/stats/tools': { tools: [{ name: 't' }] } });
    expect(d.worker).toMatchObject({ processed: null, embedded: null, failed: null, relationships: null });
    expect(d.storage).toEqual({ total: null, embedded: null, unembedded: null, users: null });
    expect(d.conv).toEqual({ conversations: null, messages: null, toolCalls: null, avgMessages: null });
    expect(d.tools[0]).toEqual({ name: 't', calls: null, successful: null, successRate: null, avgMs: null });
  });

  it('keeps a reported zero as 0', async () => {
    const d = await run({ '/api/memory/storage-stats': { total_records: 0, unembedded_records: 0 } });
    expect(d.storage.total).toBe(0);
    expect(d.storage.unembedded).toBe(0);
    expect(d.storage.embedded).toBeNull();
  });
});
