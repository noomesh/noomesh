// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi } from 'vitest';

const H = vi.hoisted(() => ({
  get: vi.fn(),
  // Capture the options useQuery was built with so the queryFn can be driven
  // directly — no React, no query client.
  lastQuery: { current: null as null | Record<string, unknown> },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ GET: H.get }),
  useQuery: (opts: Record<string, unknown>) => {
    H.lastQuery.current = opts;
    return { data: undefined, isLoading: true };
  },
}));

import { useUsage, recentMonths, compactTokens } from './useUsage';

const runQueryFn = async () => {
  const fn = H.lastQuery.current?.queryFn as () => Promise<unknown>;
  return fn();
};

describe('useUsage', () => {
  it('sends window and group as query params, and keys the cache on both', () => {
    H.get.mockResolvedValue({ data: { rows: [], totals: {} } });
    useUsage('2026-07', 'model');

    expect(H.lastQuery.current?.queryKey).toEqual(['usage', '2026-07', 'model']);
    void runQueryFn();
    expect(H.get).toHaveBeenCalledWith('/api/usage/summary', {
      params: { query: { window: '2026-07', group: 'model' } },
    });
  });

  it('totals each row and sorts biggest first', async () => {
    H.get.mockResolvedValue({
      data: {
        window: '2026-08',
        group: 'node',
        totals: { prompt_tokens: 300, completion_tokens: 120, requests: 12 },
        rows: [
          { key: 'small', prompt_tokens: 10, completion_tokens: 5, requests: 2 },
          { key: 'big', prompt_tokens: 200, completion_tokens: 100, requests: 8 },
        ],
      },
    });
    useUsage('month', 'node');
    const out = (await runQueryFn()) as { total: number; rows: { key: string; total: number }[] };

    expect(out.total).toBe(420);
    expect(out.rows.map((r) => r.key)).toEqual(['big', 'small']);
    expect(out.rows[0]!.total).toBe(300);
  });

  it('reports missing counts as null, never 0 and never NaN (i195 E1)', async () => {
    H.get.mockResolvedValue({ data: { rows: [{ key: 'x' }] } });
    useUsage('all', 'source');
    const out = (await runQueryFn()) as {
      total: number | null;
      requests: number | null;
      rows: { total: number | null; promptTokens: number | null; requests: number | null }[];
    };

    expect(out.total).toBeNull();
    expect(out.requests).toBeNull();
    expect(out.rows[0]!.total).toBeNull();
    expect(out.rows[0]!.promptTokens).toBeNull();
    expect(out.rows[0]!.requests).toBeNull();
  });

  it('a partial row has a null total and sorts after the rows that reported', async () => {
    H.get.mockResolvedValue({
      data: {
        rows: [
          { key: 'partial', prompt_tokens: 999 },
          { key: 'full', prompt_tokens: 1, completion_tokens: 1 },
        ],
      },
    });
    useUsage('all', 'source');
    const out = (await runQueryFn()) as { rows: { key: string; total: number | null }[] };
    expect(out.rows.map((r) => r.key)).toEqual(['full', 'partial']);
    expect(out.rows[1]!.total).toBeNull();
  });

  it('throws when the endpoint errors, so the panel shows its error state', async () => {
    H.get.mockResolvedValue({ error: { detail: 'nope' } });
    useUsage('month', 'node');
    await expect(runQueryFn()).rejects.toThrow('Usage API unavailable');
  });
});

describe('recentMonths', () => {
  it('walks back across a year boundary, newest first', () => {
    expect(recentMonths(4, new Date(2026, 1, 15))).toEqual([
      '2026-02',
      '2026-01',
      '2025-12',
      '2025-11',
    ]);
  });
});

describe('compactTokens', () => {
  it('shortens by magnitude', () => {
    expect(compactTokens(412)).toBe('412');
    expect(compactTokens(4_120)).toBe('4.1K');
    expect(compactTokens(4_812_366)).toBe('4.81M');
    expect(compactTokens(2_400_000_000)).toBe('2.40B');
  });
});
