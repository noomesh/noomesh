// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { noise, dotNoise, dotCacheSize } from './render';

describe('per-dot noise cache', () => {
  it('returns exactly what recomputing would, for every dot', () => {
    const id = '6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8';
    const got = dotNoise(id, 70);
    for (let k = 0; k < 70; k++) {
      expect(got[k * 3]).toBe(noise(id, k));
      expect(got[k * 3 + 1]).toBe(noise(id, k + 1000));
      expect(got[k * 3 + 2]).toBe(noise(id, k + 2000));
    }
  });

  it('grows the same entry rather than truncating when a hub gains degree', () => {
    const id = 'grows-with-degree';
    const small = Array.from(dotNoise(id, 4));
    const big = dotNoise(id, 40);
    expect(Array.from(big.slice(0, 12))).toEqual(small.slice(0, 12));
    expect(big[39 * 3]).toBe(noise(id, 39));
  });

  it('is bounded — a kiosk runs for weeks and entities come and go', () => {
    for (let i = 0; i < 700; i++) dotNoise(`churn-${i}`, 8);
    expect(dotCacheSize()).toBeLessThanOrEqual(512);
    // Still correct after a clear.
    expect(dotNoise('churn-699', 8)[0]).toBe(noise('churn-699', 0));
  });
});
