// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { rightReadout, tagAlpha } from './render';

describe('the canvas readout', () => {
  // The controller's names switch is said on the picture itself, so a
  // photo or screenshot of the wall carries it too.
  it('says LABELS ON while names are shown, and nothing about labels otherwise', () => {
    expect(rightReadout(0, 1, 'full', true)).toContain('LABELS ON');
    expect(rightReadout(0, 1, 'full', false).join(' ')).not.toMatch(/LABEL/);
  });

  it('keeps the degraded-tier line beside it', () => {
    expect(rightReadout(3, 2, 'lean', true)).toEqual(['GROWING 3', 'FOCUS ×2.0', 'ENTITY VIEW', 'LABELS ON', 'LEAN · CPU RENDER']);
  });
});

describe('hub tags', () => {
  // With names on, the tags are drawn at the wide view (zoom 1.0); with
  // them off nothing is drawn there, and the push-in fade is unchanged.
  it('draws at full strength at wide zoom when labels are on', () => {
    expect(tagAlpha(1.0, true)).toBe(1);
    expect(tagAlpha(2.5, true)).toBe(1);
  });

  it('draws nothing at wide zoom when labels are off, and fades in on push-in', () => {
    expect(tagAlpha(1.0, false)).toBe(0);
    expect(tagAlpha(1.15, false)).toBe(0);
    expect(tagAlpha(1.6, false)).toBeGreaterThan(0.4);
    expect(tagAlpha(3, false)).toBe(1);
  });
});
