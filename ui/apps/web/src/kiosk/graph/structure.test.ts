// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { structureKey } from './structure';

describe('structureKey', () => {
  it('does not change when the nodes are re-ordered — an ingest re-sorts by degree, and must not rebuild the sim', () => {
    const links = [{ src: 'a', dst: 'b' }];
    expect(structureKey(['a', 'b', 'c'], links)).toBe(structureKey(['c', 'a', 'b'], links));
  });

  it('does not change when a link is given in the other direction or re-ordered', () => {
    expect(structureKey(['a', 'b', 'c'], [{ src: 'a', dst: 'b' }, { src: 'b', dst: 'c' }])).toBe(
      structureKey(['a', 'b', 'c'], [{ src: 'c', dst: 'b' }, { src: 'b', dst: 'a' }]),
    );
  });

  it('changes when a node appears or a link appears', () => {
    const k = structureKey(['a', 'b'], [{ src: 'a', dst: 'b' }]);
    expect(structureKey(['a', 'b', 'c'], [{ src: 'a', dst: 'b' }])).not.toBe(k);
    expect(structureKey(['a', 'b'], [{ src: 'a', dst: 'b' }, { src: 'b', dst: 'a' }])).toBe(k); // same edge twice, still same set
    expect(structureKey(['a', 'b'], [])).not.toBe(k);
  });
});
