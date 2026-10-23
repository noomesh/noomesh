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

import { useSchedulerStatus, type SchedulerStatus } from './useJobs';

beforeEach(() => H.get.mockReset());

describe('useSchedulerStatus — unreported is null, never 0', () => {
  it('missing queue_depth / active_jobs / connected_clients are null', async () => {
    H.get.mockImplementation((p: string) => Promise.resolve({ data: p === '/api/scheduler/status' ? { paused: false } : {} }));
    useSchedulerStatus();
    const d = await (H.lastQuery.current!.queryFn as () => Promise<SchedulerStatus>)();
    expect(d.queued).toBeNull();
    expect(d.running).toBeNull();
    expect(d.clients).toBeNull();
  });

  it('a reported zero stays 0', async () => {
    H.get.mockImplementation((p: string) =>
      Promise.resolve({ data: p === '/api/scheduler/status' ? { queue_depth: 0, active_jobs: 0 } : { connected_clients: 0 } }),
    );
    useSchedulerStatus();
    const d = await (H.lastQuery.current!.queryFn as () => Promise<SchedulerStatus>)();
    expect([d.queued, d.running, d.clients]).toEqual([0, 0, 0]);
  });
});
