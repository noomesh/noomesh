// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Swipe recognition, pure. A horizontal swipe — touch, trackpad drag or
// mouse — switches views. Deliberately strict: it must be a clear sideways
// motion, quick, and not a tap, so a brushed-past tablet does not flip.
// Anything that fails the test is 0, and 0 does nothing.

export interface PointerSample {
  x: number;
  y: number;
  /** ms */
  t: number;
}

export const SWIPE_MIN_PX = 70;
export const SWIPE_MAX_MS = 900;
/** The vertical component must stay under this fraction of the horizontal one. */
export const SWIPE_MAX_SLOPE = 0.6;

/** -1 = swiped right (go to the previous view), +1 = swiped left (next), 0 = not a swipe. */
export function recognizeSwipe(down: PointerSample, up: PointerSample): -1 | 0 | 1 {
  const dx = up.x - down.x;
  const dy = up.y - down.y;
  const dt = up.t - down.t;
  if (dt <= 0 || dt > SWIPE_MAX_MS) return 0;
  if (Math.abs(dx) < SWIPE_MIN_PX) return 0;
  if (Math.abs(dy) > Math.abs(dx) * SWIPE_MAX_SLOPE) return 0;
  return dx < 0 ? 1 : -1;
}
