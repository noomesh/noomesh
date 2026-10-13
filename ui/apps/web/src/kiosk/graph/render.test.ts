// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { rightReadout } from './render';

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
