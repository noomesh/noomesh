// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  get: vi.fn(),
  lastQuery: { current: null as null | Record<string, unknown> },
  data: { current: undefined as unknown },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ GET: H.get }),
  useQuery: (opts: Record<string, unknown>) => {
    H.lastQuery.current = opts;
    return { data: H.data.current };
  },
}));

import { useConsolePieces, type ConsolePieces } from './useConsolePieces';

const slot = (t: string) => ({ title: t, description: `${t} d`, steps: ['a'] });

/** Drives the queryFn directly — no React, no query client. */
async function run(
  addons: Record<string, string>,
  pieces: Record<string, unknown | Error>,
): Promise<ConsolePieces> {
  H.get.mockImplementation((path: string, opts?: { params?: { path?: { addon_id?: string } } }) => {
    if (path === '/health') return Promise.resolve({ data: { addons } });
    const id = opts?.params?.path?.addon_id ?? '';
    const p = pieces[id];
    if (p instanceof Error) return Promise.reject(p);
    return Promise.resolve({ data: p });
  });
  useConsolePieces();
  const fn = H.lastQuery.current?.queryFn as () => Promise<ConsolePieces>;
  return fn();
}

beforeEach(() => {
  H.get.mockReset();
  H.data.current = undefined;
});

describe('useConsolePieces', () => {
  it('merges the slots of every enabled slot owner', async () => {
    const out = await run(
      { evolve: 'enabled', trellion_intel: 'enabled', trellion: 'enabled' },
      {
        evolve: { version: 1, addon: 'evolve', slots: { 'evolve:ga': slot('GA') } },
        trellion_intel: { version: 1, addon: 'trellion_intel', slots: { 'trellion_intel:temporal': slot('T') } },
      },
    );
    expect(Object.keys(out).sort()).toEqual(['evolve:ga', 'trellion_intel:temporal']);
    expect(out['evolve:ga']).toEqual({ title: 'GA', description: 'GA d', steps: ['a'] });
  });

  it('does not ask for add-ons that are disabled or own no slots', async () => {
    await run({ evolve: 'disabled', trellion_intel: 'unhealthy', trellion: 'enabled' }, {});
    const asked = H.get.mock.calls.map((c) => c[0]);
    expect(asked).toEqual(['/health']);
  });

  it('leaves a failing add-on absent without throwing', async () => {
    const out = await run(
      { evolve: 'enabled', trellion_intel: 'enabled' },
      {
        evolve: new Error('502'),
        trellion_intel: { version: 1, addon: 'trellion_intel', slots: { 'trellion_intel:graph-nav': slot('G') } },
      },
    );
    expect(Object.keys(out)).toEqual(['trellion_intel:graph-nav']);
  });

  it('accepts a slot with no steps and an add-on with no slots', async () => {
    const out = await run(
      { evolve: 'enabled', trellion_intel: 'enabled' },
      {
        evolve: { version: 1, addon: 'evolve', slots: { 'evolve:ga': { title: 'GA', description: 'd' } } },
        trellion_intel: { version: 1, addon: 'trellion_intel', slots: {} },
      },
    );
    expect(out).toEqual({ 'evolve:ga': { title: 'GA', description: 'd' } });
  });

  it('asks only the add-ons the slot registry names', async () => {
    await run({ evolve: 'enabled', trellion_intel: 'enabled', trellion: 'enabled', other: 'enabled' }, {});
    const ids = H.get.mock.calls.slice(1).map((c) => c[1].params.path.addon_id).sort();
    expect(ids).toEqual(['evolve', 'trellion_intel']);
  });

  it('survives /health failing', async () => {
    H.get.mockRejectedValue(new Error('down'));
    useConsolePieces();
    const fn = H.lastQuery.current?.queryFn as () => Promise<ConsolePieces>;
    await expect(fn()).resolves.toEqual({});
  });

  it('drops slots outside the add-on prefix or with the wrong types', async () => {
    const out = await run(
      { evolve: 'enabled' },
      {
        evolve: {
          version: 1,
          addon: 'evolve',
          slots: {
            'evolve:ok': slot('ok'),
            'trellion_intel:stolen': slot('x'),
            'evolve:badtitle': { title: 1, description: 'd', steps: [] },
            'evolve:badsteps': { title: 't', description: 'd', steps: [2] },
          },
        },
      },
    );
    expect(Object.keys(out)).toEqual(['evolve:ok']);
  });

  it('returns {} until the query has data', () => {
    expect(useConsolePieces()).toEqual({});
  });

  it('returns the query data once loaded', () => {
    H.data.current = { 'evolve:ga': slot('GA') };
    expect(useConsolePieces()).toBe(H.data.current);
  });
});
