// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { recognizeSwipe, SWIPE_MIN_PX, SWIPE_MAX_MS } from './gesture';

const at = (x: number, y: number, t: number) => ({ x, y, t });

describe('recognizeSwipe', () => {
  it('a quick leftward drag is +1 (next), rightward is -1 (previous)', () => {
    expect(recognizeSwipe(at(500, 300, 0), at(300, 310, 300))).toBe(1);
    expect(recognizeSwipe(at(300, 300, 0), at(500, 290, 300))).toBe(-1);
  });

  it('a tap is not a swipe', () => {
    expect(recognizeSwipe(at(500, 300, 0), at(504, 302, 120))).toBe(0);
  });

  it('too short a distance is not a swipe', () => {
    expect(recognizeSwipe(at(500, 300, 0), at(500 - SWIPE_MIN_PX + 1, 300, 200))).toBe(0);
    expect(recognizeSwipe(at(500, 300, 0), at(500 - SWIPE_MIN_PX, 300, 200))).toBe(1);
  });

  it('too slow is not a swipe — a hand resting on the glass and drifting', () => {
    expect(recognizeSwipe(at(500, 300, 0), at(200, 300, SWIPE_MAX_MS + 1))).toBe(0);
  });

  it('a mostly vertical motion is not a swipe', () => {
    expect(recognizeSwipe(at(500, 300, 0), at(400, 500, 300))).toBe(0);
  });

  it('a non-positive duration is not a swipe', () => {
    expect(recognizeSwipe(at(500, 300, 10), at(300, 300, 10))).toBe(0);
  });
});
