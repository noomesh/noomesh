// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi } from 'vitest';
import {
  OPEN_GRAFANA_HASH,
  AUTO_OPEN_GAP_MS,
  AUTO_OPEN_KEY,
  arrivalPanel,
  arrivalAsksForGrafana,
  mayAutoOpen,
  lastAutoOpen,
  recordAutoOpen,
  clearArrival,
} from './grafanaArrival';

describe('arriving from a bookmark of Grafana', () => {
  it('reads the hash noo-cli derives (tailnet_serve::console_open_grafana_url)', () => {
    expect(OPEN_GRAFANA_HASH).toBe('#/observability?open=grafana');
    expect(arrivalPanel(OPEN_GRAFANA_HASH)).toBe('observability');
    expect(arrivalAsksForGrafana(OPEN_GRAFANA_HASH)).toBe(true);
  });

  it('routes #/observability alone to the panel without opening anything', () => {
    expect(arrivalPanel('#/observability')).toBe('observability');
    expect(arrivalAsksForGrafana('#/observability')).toBe(false);
    expect(arrivalAsksForGrafana('#/observability?open=other')).toBe(false);
  });

  it('ignores everything else', () => {
    for (const h of ['', '#', '#/cluster', '#/observabilityx?open=grafana', '#observability?open=grafana']) {
      expect(arrivalPanel(h)).toBeNull();
      expect(arrivalAsksForGrafana(h)).toBe(false);
    }
  });

  it('opens once, then refuses a bounce inside the gap (a Grafana rejecting every token)', () => {
    const t = 1_000_000;
    expect(mayAutoOpen(null, t)).toBe(true);
    expect(mayAutoOpen(t, t + 5_000)).toBe(false);
    // A session that expired after its 5 minutes is a fresh arrival.
    expect(mayAutoOpen(t, t + AUTO_OPEN_GAP_MS)).toBe(true);
    expect(mayAutoOpen(t, t + 15 * 60_000)).toBe(true);
    // A clock that went backwards is not a loop.
    expect(mayAutoOpen(t, t - 1)).toBe(true);
  });

  it('keeps the guard in per-tab storage and survives blocked storage', () => {
    const m = new Map<string, string>();
    const store = () => ({ getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) });
    expect(lastAutoOpen(store)).toBeNull();
    recordAutoOpen(store, 42);
    expect(m.get(AUTO_OPEN_KEY)).toBe('42');
    expect(lastAutoOpen(store)).toBe(42);
    const blocked = () => {
      throw new Error('SecurityError');
    };
    expect(lastAutoOpen(blocked)).toBeNull();
    expect(() => recordAutoOpen(blocked, 1)).not.toThrow();
  });

  it('drops the hash so a reload does not reopen Grafana', () => {
    const replaceState = vi.fn();
    clearArrival({
      location: { pathname: '/obtest/', search: '' } as Location,
      history: { state: null, replaceState } as unknown as History,
    });
    expect(replaceState).toHaveBeenCalledWith(null, '', '/obtest/');
  });
});
