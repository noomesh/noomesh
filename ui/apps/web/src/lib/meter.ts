// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

/**
 * Threshold colouring for the little inline meters.
 *
 * Direction matters and is easy to get backwards: a high backend load is bad,
 * a high tool success rate is good. Callers say which, and the level is
 * computed against a single normalised scale so the palette means the same
 * thing everywhere — green fine, amber worth a look, red wrong.
 */
export type MeterDirection = 'high-bad' | 'high-good';

export type MeterLevel = 'ok' | 'warn' | 'bad';

/** `pct` is 0–100. */
export function meterLevel(pct: number, direction: MeterDirection): MeterLevel {
  // Normalise so that a larger number always means "worse".
  const severity = direction === 'high-good' ? 100 - pct : pct;
  if (severity >= 85) return 'bad';
  if (severity >= 60) return 'warn';
  return 'ok';
}
