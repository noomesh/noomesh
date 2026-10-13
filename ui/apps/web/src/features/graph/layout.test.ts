// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { layoutGraph, radiusFor, colorFor } from './layout';

const chain = (n: number) => ({
  nodes: Array.from({ length: n }, (_, i) => ({
    id: `n${i}`,
    name: `Node ${i}`,
    type: i % 2 ? 'person' : 'org',
    degree: 2,
  })),
  edges: Array.from({ length: n - 1 }, (_, i) => ({
    src: `n${i}`,
    dst: `n${i + 1}`,
    relType: 'KNOWS',
  })),
});

describe('layoutGraph', () => {
  it('is deterministic — the same graph lays out identically', () => {
    const a = layoutGraph(chain(12));
    const b = layoutGraph(chain(12));
    // A refetch every 30s must not scramble the picture.
    expect(a.nodes.map((n) => [n.x, n.y])).toEqual(b.nodes.map((n) => [n.x, n.y]));
  });

  it('keeps every node inside the viewport', () => {
    const out = layoutGraph(chain(40));
    for (const n of out.nodes) {
      expect(n.x).toBeGreaterThanOrEqual(0);
      expect(n.x).toBeLessThanOrEqual(out.width);
      expect(n.y).toBeGreaterThanOrEqual(0);
      expect(n.y).toBeLessThanOrEqual(out.height);
      expect(Number.isFinite(n.x) && Number.isFinite(n.y)).toBe(true);
    }
  });

  it('drops edges whose endpoints are outside the returned window', () => {
    const out = layoutGraph({
      nodes: [{ id: 'a', name: 'A', type: 't', degree: 1 }],
      edges: [
        { src: 'a', dst: 'missing', relType: 'R' },
        { src: 'nope', dst: 'a', relType: 'R' },
      ],
    });
    // The far endpoint exists in the graph, just not in this page of it —
    // drawing a line to nowhere would be a lie.
    expect(out.edges).toHaveLength(0);
    expect(out.nodes).toHaveLength(1);
  });

  it('separates coincident nodes instead of producing NaN', () => {
    // No edges, identical seeds would otherwise divide by a zero distance.
    const out = layoutGraph({
      nodes: [
        { id: 'a', name: 'A', type: 't', degree: 0 },
        { id: 'b', name: 'B', type: 't', degree: 0 },
      ],
      edges: [],
    });
    for (const n of out.nodes) {
      expect(Number.isNaN(n.x)).toBe(false);
      expect(Number.isNaN(n.y)).toBe(false);
    }
    const [a, b] = out.nodes;
    expect(Math.hypot(a!.x - b!.x, a!.y - b!.y)).toBeGreaterThan(1);
  });

  it('handles an empty graph', () => {
    const out = layoutGraph({ nodes: [], edges: [] });
    expect(out.nodes).toEqual([]);
    expect(out.edges).toEqual([]);
  });

  it('pulls connected nodes closer than unconnected ones', () => {
    const out = layoutGraph({
      nodes: [
        { id: 'a', name: 'A', type: 't', degree: 1 },
        { id: 'b', name: 'B', type: 't', degree: 1 },
        { id: 'c', name: 'C', type: 't', degree: 0 },
      ],
      edges: [{ src: 'a', dst: 'b', relType: 'R' }],
    });
    const at = out.nodes.find((n) => n.id === 'a')!;
    const bt = out.nodes.find((n) => n.id === 'b')!;
    const ct = out.nodes.find((n) => n.id === 'c')!;
    const linked = Math.hypot(at.x - bt.x, at.y - bt.y);
    const loose = Math.min(
      Math.hypot(at.x - ct.x, at.y - ct.y),
      Math.hypot(bt.x - ct.x, bt.y - ct.y),
    );
    expect(linked).toBeLessThan(loose);
  });
});

describe('radiusFor', () => {
  it('scales sub-linearly so a hub does not dwarf the graph', () => {
    const small = radiusFor(1, 100);
    const hub = radiusFor(100, 100);
    expect(hub).toBeGreaterThan(small);
    // sqrt scaling: 100x the degree is far less than 100x the radius.
    expect(hub / small).toBeLessThan(5);
  });

  it('survives a graph where every degree is zero', () => {
    expect(Number.isFinite(radiusFor(0, 0))).toBe(true);
  });
});

describe('colorFor', () => {
  it('is stable per type', () => {
    expect(colorFor('person')).toBe(colorFor('person'));
    expect(colorFor('person')).not.toBe(colorFor(''));
  });
});
