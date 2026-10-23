// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  invalidate: vi.fn(),
  // Capture the options useQuery/useMutation were built with so their
  // functions can be driven directly — no React, no query client.
  lastQuery: { current: null as null | Record<string, unknown> },
  lastMutation: { current: null as null | Record<string, unknown> },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ GET: H.get, POST: H.post }),
  useQueryClient: () => ({ invalidateQueries: H.invalidate }),
  useQuery: (opts: Record<string, unknown>) => {
    H.lastQuery.current = opts;
    return { data: undefined, isLoading: true };
  },
  useMutation: (opts: Record<string, unknown>) => {
    H.lastMutation.current = opts;
    return {};
  },
}));

import {
  useStagedPrunes,
  useRestorePrune,
  parsePgTime,
  daysLeft,
  RETENTION_DAYS,
  type StagedPrunes,
  type RestoreOutcome,
} from './usePrunes';

const DAY = 86_400_000;
const runQuery = () => (H.lastQuery.current?.queryFn as () => Promise<StagedPrunes>)();
const runRestore = (row: { kind: 'entity' | 'edge'; stagingId: string }) =>
  (H.lastMutation.current?.mutationFn as (r: typeof row) => Promise<RestoreOutcome>)(row);

beforeEach(() => {
  H.get.mockReset();
  H.post.mockReset();
  H.invalidate.mockReset();
});

describe('parsePgTime', () => {
  it('reads the timestamptz::text form the handler returns', () => {
    expect(parsePgTime('2026-09-20 06:00:01.123456+00')).toBe(Date.UTC(2026, 8, 20, 6, 0, 1, 123));
    expect(parsePgTime('2026-09-20 08:00:00+02')).toBe(Date.UTC(2026, 8, 20, 6, 0, 0));
  });
  it('still reads ISO, and returns null for junk rather than NaN', () => {
    expect(parsePgTime('2026-09-20T06:00:00Z')).toBe(Date.UTC(2026, 8, 20, 6));
    expect(parsePgTime('not a time')).toBeNull();
    expect(parsePgTime(null)).toBeNull();
  });
});

describe('daysLeft', () => {
  it('rounds up and floors at zero', () => {
    const now = Date.UTC(2026, 8, 27);
    expect(daysLeft(now + 2.5 * DAY, now)).toBe(3);
    expect(daysLeft(now - DAY, now)).toBe(0);
    expect(daysLeft(null, now)).toBeNull();
  });
});

describe('useStagedPrunes', () => {
  it('asks for the staged list with the handler default limit', () => {
    H.get.mockResolvedValue({ data: { staged: [] } });
    useStagedPrunes();
    expect(H.lastQuery.current?.queryKey).toEqual(['graph', 'prune', 'staged']);
    void runQuery();
    expect(H.get).toHaveBeenCalledWith('/api/v1/graph/prune/staged', {
      params: { query: { limit: 200 } },
    });
  });

  it('merges entities and edges newest first, with a purge date 30 days after staging', async () => {
    H.get.mockResolvedValue({
      data: {
        staged: [
          {
            staging_id: 's-ent',
            entity_id: 'e1',
            canonical_name: 'Acme',
            entity_type: 'ORG',
            reason: 'orphan',
            staged_at: '2026-09-20 06:00:00+00',
            run_id: 'run1',
            edge_count: 2,
            mention_count: 5,
          },
        ],
        counts: { orphan: 3, junk: 1 },
        staged_edges: [
          {
            staging_id: 's-edge',
            edge_id: 'x',
            rel_type: 'WORKS_AT',
            reason: 'weak_old',
            staged_at: '2026-09-21 06:00:00+00',
            confidence: 0.1,
            src_name: 'Bob',
            dst_name: 'Acme',
          },
        ],
        edge_counts: { weak_old: 1 },
      },
    });
    useStagedPrunes();
    const out = await runQuery();

    expect(out.rows.map((r) => r.stagingId)).toEqual(['s-edge', 's-ent']);
    expect(out.rows[0]).toMatchObject({ kind: 'edge', label: 'Bob —WORKS_AT→ Acme', confidence: 0.1 });
    expect(out.rows[1]).toMatchObject({ kind: 'entity', label: 'Acme', detail: 'ORG', edgeCount: 2, runId: 'run1' });
    expect(out.rows[1]!.purgeAt).toBe(Date.UTC(2026, 8, 20, 6) + RETENTION_DAYS * DAY);
    // Totals come from the whole table, not the page.
    expect(out.entityTotal).toBe(4);
    expect(out.edgeTotal).toBe(1);
    expect(out.note).toBeNull();
  });

  it('passes the never-ran note through on an empty list', async () => {
    H.get.mockResolvedValue({
      data: { staged: [], counts: {}, note: 'staging table not created yet — graph_prune has not run' },
    });
    useStagedPrunes();
    const out = await runQuery();
    expect(out.rows).toEqual([]);
    expect(out.note).toMatch(/has not run/);
  });

  it('throws when the endpoint errors, so the view shows its error state', async () => {
    H.get.mockResolvedValue({ error: { detail: 'nope' } });
    useStagedPrunes();
    await expect(runQuery()).rejects.toThrow('Prune staging API unavailable');
  });
});

describe('useRestorePrune', () => {
  it('sends an entity in staging_ids and an edge in edge_staging_ids', async () => {
    H.post.mockResolvedValue({ data: { results: [{ staging_id: 'a', status: 'restored' }] } });
    useRestorePrune();
    await runRestore({ kind: 'entity', stagingId: 'a' });
    expect(H.post).toHaveBeenLastCalledWith('/api/v1/graph/prune/restore', {
      body: { staging_ids: ['a'] },
    });

    H.post.mockResolvedValue({ data: { results: [{ staging_id: 'b', status: 'restored' }] } });
    await runRestore({ kind: 'edge', stagingId: 'b' });
    expect(H.post).toHaveBeenLastCalledWith('/api/v1/graph/prune/restore', {
      body: { edge_staging_ids: ['b'] },
    });
  });

  it('reports what the restore did', async () => {
    H.post.mockResolvedValue({
      data: {
        results: [
          { staging_id: 'a', status: 'restored', grafted_onto_existing: true, edges_restored: 3, edges_skipped: 1 },
        ],
      },
    });
    useRestorePrune();
    await expect(runRestore({ kind: 'entity', stagingId: 'a' })).resolves.toEqual({
      status: 'restored',
      grafted: true,
      edgesRestored: 3,
      edgesSkipped: 1,
    });
  });

  it('turns a 200 carrying not_found or error into a failure, not a silent success', async () => {
    useRestorePrune();
    H.post.mockResolvedValue({ data: { results: [{ staging_id: 'a', status: 'not_found' }] } });
    await expect(runRestore({ kind: 'entity', stagingId: 'a' })).rejects.toThrow(/Not found/);

    H.post.mockResolvedValue({
      data: { results: [{ staging_id: 'a', status: 'error', error: 'malformed payload' }] },
    });
    await expect(runRestore({ kind: 'entity', stagingId: 'a' })).rejects.toThrow('malformed payload');
  });

  it('treats already_restored as done', async () => {
    H.post.mockResolvedValue({ data: { results: [{ staging_id: 'a', status: 'already_restored' }] } });
    useRestorePrune();
    await expect(runRestore({ kind: 'entity', stagingId: 'a' })).resolves.toMatchObject({
      status: 'already_restored',
    });
  });

  it('names the role on a 403', async () => {
    H.post.mockResolvedValue({ error: {}, response: { status: 403 } });
    useRestorePrune();
    await expect(runRestore({ kind: 'edge', stagingId: 'b' })).rejects.toThrow(/operator role/);
  });

  it('refetches the graph (list and map) once settled', () => {
    useRestorePrune();
    (H.lastMutation.current?.onSettled as () => void)();
    expect(H.invalidate).toHaveBeenCalledWith({ queryKey: ['graph'] });
  });
});

describe('usePrunes — unreported is null, never 0 (i195 E1)', () => {
  it('entity edge/mention counts and totals are null when the gateway sends none', async () => {
    H.get.mockResolvedValue({ data: { staged: [{ staging_id: 's1', canonical_name: 'A' }] } });
    useStagedPrunes();
    const out = (await (H.lastQuery.current!.queryFn as () => Promise<StagedPrunes>)());
    expect(out.rows[0]!.edgeCount).toBeNull();
    expect(out.rows[0]!.mentionCount).toBeNull();
    expect(out.entityTotal).toBeNull();
    expect(out.edgeTotal).toBeNull();
  });
});
