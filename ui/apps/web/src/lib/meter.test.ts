// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { meterLevel } from './meter';

describe('meterLevel', () => {
  it('treats a high value as bad when the caller says high-bad', () => {
    expect(meterLevel(10, 'high-bad')).toBe('ok');
    expect(meterLevel(70, 'high-bad')).toBe('warn');
    expect(meterLevel(95, 'high-bad')).toBe('bad');
  });

  it('inverts for high-good — a low tool success rate is the problem', () => {
    expect(meterLevel(98, 'high-good')).toBe('ok');
    expect(meterLevel(35, 'high-good')).toBe('warn');
    expect(meterLevel(5, 'high-good')).toBe('bad');
  });

  it('never disagrees with itself at the boundaries', () => {
    // The whole point of the helper is that green/amber/red mean the same
    // thing on every meter regardless of which way the metric points.
    expect(meterLevel(0, 'high-bad')).toBe(meterLevel(100, 'high-good'));
    expect(meterLevel(100, 'high-bad')).toBe(meterLevel(0, 'high-good'));
  });
});
