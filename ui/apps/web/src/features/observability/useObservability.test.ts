// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  get: vi.fn(),
  lastQuery: { current: null as null | Record<string, unknown> },
  isOperator: { current: true },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ GET: H.get }),
  useAuth: () => ({ isOperator: H.isOperator.current }),
  useQuery: (opts: Record<string, unknown>) => {
    H.lastQuery.current = opts;
    return { data: undefined, isLoading: true };
  },
}));

import { useObservability, type ObsData } from './useObservability';

/** Drives the queryFn directly — no React, no query client. */
async function run(health: unknown): Promise<ObsData> {
  H.get.mockImplementation((path: string) => {
    if (path === '/health') return Promise.resolve({ data: health });
    return Promise.resolve({ data: {} });
  });
  useObservability();
  const fn = H.lastQuery.current?.queryFn as () => Promise<ObsData>;
  return fn();
}

beforeEach(() => { H.get.mockReset(); H.isOperator.current = true; });

describe('useObservability — add-ons', () => {
  // The gateway builds `addons` from its ADDONS table, so a new add-on appears
  // with no schema change. A console that knew a fixed list would drop it.
  it('renders whatever keys the gateway sends, including unknown ones', async () => {
    const d = await run({
      status: 'healthy',
      addons: { trellion: 'enabled', trellion_intel: 'disabled', something_new: 'enabled' },
    });
    expect(d.addons.map((a) => a.id)).toEqual(['trellion', 'trellion_intel', 'something_new']);
  });

  it('labels the known add-ons and humanises the rest', async () => {
    const d = await run({ status: 'healthy', addons: { trellion_intel: 'enabled', odd_one: 'enabled' } });
    expect(d.addons[0]!.label).toBe('Trellion Intel (adaptive retrieval)');
    expect(d.addons[1]!.label).toBe('Odd One');
  });

  it('reads enabled/disabled correctly', async () => {
    const d = await run({ status: 'healthy', addons: { a: 'enabled', b: 'disabled' } });
    expect(d.addons.map((x) => x.state)).toEqual(['enabled', 'disabled']);
  });

  // `disabled` is a choice, `unhealthy` is a fault. The first cut of this panel
  // used a boolean, which would have rendered a broken add-on as "switched
  // off" — exactly the confusion addons.rs exists to prevent. Not emitted by
  // the gateway yet; handled so it is right on arrival.
  it('keeps unhealthy distinct from disabled', async () => {
    const d = await run({ status: 'healthy', addons: { a: 'disabled', b: 'unhealthy' } });
    expect(d.addons.map((x) => x.state)).toEqual(['disabled', 'unhealthy']);
  });

  it('calls an unrecognised state unknown rather than guessing', async () => {
    // Neither green nor red: guessing either way is worse than saying so.
    const d = await run({ status: 'healthy', addons: { a: 'degraded-ish', b: null } });
    expect(d.addons.map((x) => x.state)).toEqual(['unknown', 'unknown']);
  });

  // The whole reason add-ons are a separate list from `deps`: the gateway is
  // explicit that a disabled add-on "must see 'disabled', never degraded-red".
  // Leaking one into deps would paint an operator's own choice as a fault.
  it('never puts an add-on in the dependency list', async () => {
    const d = await run({
      status: 'healthy',
      dependencies: { postgresql: { healthy: true } },
      addons: { trellion: 'disabled' },
    });
    expect(d.deps.map((x) => x.name)).toEqual(['Gateway', 'Postgres', 'NATS', 'Redis']);
    expect(d.deps.some((x) => x.status === 'down')).toBe(false);
  });

  it('is empty rather than broken when the gateway omits addons', async () => {
    // Older gateways predate the field; absent must not become a fake row.
    const d = await run({ status: 'healthy' });
    expect(d.addons).toEqual([]);
  });
});

describe('container stats are operator-only', () => {
  it('does not call the log route below the operator role, and says so', async () => {
    H.isOperator.current = false;
    const d = await run({ status: 'healthy' });
    expect(H.get.mock.calls.map((c) => c[0])).not.toContain('/api/logs/docker-stats');
    expect(d.containersAvailable).toBe(false);
    expect(d.containers).toEqual([]);
  });

  it('calls it for an operator', async () => {
    const d = await run({ status: 'healthy' });
    expect(H.get.mock.calls.map((c) => c[0])).toContain('/api/logs/docker-stats');
    expect(d.containersAvailable).toBe(true);
  });
});
