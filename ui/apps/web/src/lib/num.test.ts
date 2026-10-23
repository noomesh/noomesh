// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { num, scale, sumOrNull, ratioOrNull, dash, compareNullable, DASH } from './num';

describe('num helpers (i195 E1: unreported is a dash, never 0)', () => {
  it('num: only finite numbers survive, zero included', () => {
    expect(num(0)).toBe(0);
    expect(num(4)).toBe(4);
    expect(num(undefined)).toBeNull();
    expect(num(null)).toBeNull();
    expect(num('3')).toBeNull();
    expect(num(NaN)).toBeNull();
    expect(num(Infinity)).toBeNull();
  });
  it('scale keeps null', () => {
    expect(scale(null, 2)).toBeNull();
    expect(scale(3, 2)).toBe(6);
  });
  it('sumOrNull is null if any input is null; an empty sum is 0', () => {
    expect(sumOrNull(1, 2, 3)).toBe(6);
    expect(sumOrNull(1, null, 3)).toBeNull();
    expect(sumOrNull()).toBe(0);
  });
  it('ratioOrNull is null for a null input or a zero divisor', () => {
    expect(ratioOrNull(1, 4)).toBe(0.25);
    expect(ratioOrNull(null, 4)).toBeNull();
    expect(ratioOrNull(1, null)).toBeNull();
    expect(ratioOrNull(1, 0)).toBeNull();
    expect(ratioOrNull(0, 4)).toBe(0);
  });
  it('dash renders null/undefined as a dash and a reported zero as 0', () => {
    expect(dash(null)).toBe(DASH);
    expect(dash(undefined)).toBe(DASH);
    expect(dash(0)).toBe('0');
    expect(dash(1234)).toBe((1234).toLocaleString());
    expect(dash(5, (n) => `${n}%`)).toBe('5%');
  });
  it('compareNullable sorts nulls last in both directions', () => {
    const asc = [3, null, 1, 2].sort((a, b) => compareNullable(a, b));
    expect(asc).toEqual([1, 2, 3, null]);
    const desc = [3, null, 1, 2].sort((a, b) => compareNullable(a, b, -1));
    expect(desc).toEqual([3, 2, 1, null]);
  });
});
