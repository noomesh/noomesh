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

describe('GPU telemetry the gateway did not send', () => {
  /** Same driver as `run`, with a gpu-metrics payload. */
  async function runGpus(gpus: unknown[]): Promise<ObsData> {
    H.get.mockImplementation((path: string) => {
      if (path === '/health') return Promise.resolve({ data: { status: 'healthy' } });
      if (path === '/api/cluster/gpu-metrics') return Promise.resolve({ data: { gpus } });
      return Promise.resolve({ data: {} });
    });
    useObservability();
    const fn = H.lastQuery.current?.queryFn as () => Promise<ObsData>;
    return fn();
  }

  it('is null, not 0: an unreported temperature is not a cold GPU', async () => {
    const d = await runGpus([{ index: 0, name: 'A' }]);
    expect(d.gpus).toHaveLength(1);
    expect(d.gpus[0].temp).toBeNull();
    expect(d.gpus[0].util).toBeNull();
    expect(d.gpus[0].power).toBeNull();
    expect(d.gpus[0].vramUsed).toBeNull();
    expect(d.gpus[0].vramTotal).toBeNull();
  });

  it('keeps a reported number, zero included, and scales memory to GB', async () => {
    const d = await runGpus([
      { index: 1, name: 'B', temperature: 0, utilization: 42, power: 180.4, memory_used: 2048, memory_total: 8192 },
    ]);
    expect(d.gpus[0].temp).toBe(0);
    expect(d.gpus[0].util).toBe(42);
    expect(d.gpus[0].power).toBeCloseTo(180.4);
    expect(d.gpus[0].vramUsed).toBe(2);
    expect(d.gpus[0].vramTotal).toBe(8);
  });

  it('treats a non-numeric value as unreported', async () => {
    const d = await runGpus([{ index: 2, name: 'C', temperature: 'N/A', utilization: null }]);
    expect(d.gpus[0].temp).toBeNull();
    expect(d.gpus[0].util).toBeNull();
  });
});

describe('useObservability — container stats', () => {
  it('unreported cpu/mem are null, not 0 (i195 E1)', async () => {
    H.get.mockImplementation((path: string) => {
      if (path === '/api/logs/docker-stats') return Promise.resolve({ data: { containers: [{ name: 'x' }] } });
      return Promise.resolve({ data: {} });
    });
    useObservability();
    const d = await (H.lastQuery.current?.queryFn as () => Promise<ObsData>)();
    expect(d.containers[0]).toMatchObject({ name: 'x', cpu: null, memUsed: null, memLimit: null, memPct: null });
  });
});
