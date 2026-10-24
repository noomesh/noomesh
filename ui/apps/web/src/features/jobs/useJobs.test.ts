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

import { useSchedulerStatus, refusalMessage, type SchedulerStatus } from './useJobs';

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

describe('a Redis outage', () => {
  it('shows the gateway sentence and the retry, not the machine code', () => {
    const body = { error: 'redis_reconnecting', detail: 'Redis not connected: retry shortly', retry_after_secs: 5 };
    expect(refusalMessage(body, 'Jobs API unavailable')).toBe('Redis not connected: retry shortly Retry in 5s.');
  });

  it('falls back when the body carries no detail', () => {
    expect(refusalMessage({ error: 'x' }, 'Cancel failed')).toBe('Cancel failed');
    expect(refusalMessage(undefined, 'Cancel failed')).toBe('Cancel failed');
  });

  it('a null paused flag stays null, never false', async () => {
    H.get.mockImplementation((p: string) =>
      Promise.resolve({ data: p === '/api/scheduler/status' ? { paused: null, queue_depth: null } : {} }),
    );
    useSchedulerStatus();
    const d = await (H.lastQuery.current!.queryFn as () => Promise<SchedulerStatus>)();
    expect(d.paused).toBeNull();
    expect(d.queued).toBeNull();
  });
});
