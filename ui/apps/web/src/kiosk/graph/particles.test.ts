// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { createParticles } from './particles';

const links = [
  { a: 0, b: 1 },
  { a: 1, b: 2 },
  { a: 3, b: 4 },
];

describe('particles', () => {
  it('a burst spawns only on links touching the target, travelling toward it', () => {
    const f = createParticles();
    f.burst(1, links, 2);
    expect(f.items).toHaveLength(4);
    expect(f.items.every((p) => p.link === 0 || p.link === 1)).toBe(true);
    // link 0 is a→b with b = 1: forward; link 1 is a=1→b: backward
    expect(f.items.filter((p) => p.link === 0).every((p) => p.forward)).toBe(true);
    expect(f.items.filter((p) => p.link === 1).every((p) => !p.forward)).toBe(true);
    expect(f.items.every((p) => p.intensity === 1)).toBe(true);
  });

  it('particles advance and expire past the end of the link', () => {
    const f = createParticles();
    f.trickle(links.length);
    expect(f.items).toHaveLength(1);
    f.step(2);
    expect(f.items).toHaveLength(1);
    f.step(10);
    expect(f.items).toHaveLength(0);
  });

  it('trickle is faint and does nothing with no links', () => {
    const f = createParticles();
    f.trickle(0);
    expect(f.items).toHaveLength(0);
    f.trickle(3);
    expect(f.items[0]!.intensity).toBeLessThan(1);
  });

  it('is deterministic for a seed', () => {
    const a = createParticles(9);
    const b = createParticles(9);
    a.burst(1, links, 3);
    b.burst(1, links, 3);
    expect(a.items).toEqual(b.items);
  });
});
