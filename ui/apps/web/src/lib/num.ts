// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The console rule (i195 E1): a number the gateway did not send renders as a
// dash, never 0. A zero is a measurement ("nothing queued"); an absent field
// is the absence of one. Parse with `num()`, carry `null` through arithmetic
// with the helpers below, and render with `dash()`.

/** The glyph every unreported number renders as. */
export const DASH = '—';

/** A reported number, or null when the field is absent or not a finite number. */
export function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

/** Scale a reported number; null stays null. */
export function scale(v: number | null, k: number): number | null {
  return v === null ? null : v * k;
}

/** Sum of the inputs; null if ANY input is null (a partial sum is a wrong number). */
export function sumOrNull(...vs: Array<number | null>): number | null {
  let t = 0;
  for (const v of vs) {
    if (v === null) return null;
    t += v;
  }
  return t;
}

/** a / b as a ratio; null if either input is null or the divisor is 0. */
export function ratioOrNull(a: number | null, b: number | null): number | null {
  return a === null || b === null || b === 0 ? null : a / b;
}

/** Render a nullable number: a dash when null, else `fmt(v)` (default toLocaleString). */
export function dash(v: number | null | undefined, fmt: (n: number) => string = (n) => n.toLocaleString()): string {
  return v === null || v === undefined ? DASH : fmt(v);
}

/** Comparator for ascending sort on a nullable column; nulls last. Negate-free: pass dir -1 for descending (nulls still last). */
export function compareNullable(a: number | null, b: number | null, dir: 1 | -1 = 1): number {
  if (a === null && b === null) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return (a - b) * dir;
}
