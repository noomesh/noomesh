// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import { createSim } from './sim';

const ring = (n: number) =>
  Array.from({ length: n }, (_, i) => ({
    id: `c${i}`,
    mass: 1 + (i % 4),
    x0: Math.cos((i / n) * Math.PI * 2),
    y0: Math.sin((i / n) * Math.PI * 2),
  }));
const chain = (n: number) => Array.from({ length: n - 1 }, (_, i) => ({ a: `c${i}`, b: `c${i + 1}`, weight: 1 + (i % 3) }));

const run = (sim: ReturnType<typeof createSim>, seconds: number, activity: Record<string, number> = {}) => {
  for (let t = 0; t < seconds; t += 1 / 30) sim.step(1 / 30, activity);
};

describe('graph sim', () => {
  it('is deterministic for a seed', () => {
    const a = createSim({ nodes: ring(8), links: chain(8), seed: 3 });
    const b = createSim({ nodes: ring(8), links: chain(8), seed: 3 });
    run(a, 5);
    run(b, 5);
    expect(a.project(5)).toEqual(b.project(5));
  });

  it('stays bounded and never collapses to a point', () => {
    const sim = createSim({ nodes: ring(12), links: chain(12) });
    run(sim, 30);
    const f = sim.project(30);
    for (const p of f.nodes) {
      expect(Math.abs(p.x)).toBeLessThan(3);
      expect(Math.abs(p.y)).toBeLessThan(3);
      expect(p.depth).toBeGreaterThanOrEqual(0);
      expect(p.depth).toBeLessThanOrEqual(1);
    }
    const spread = Math.max(...f.nodes.map((p) => p.x)) - Math.min(...f.nodes.map((p) => p.x));
    expect(spread).toBeGreaterThan(0.3);
  });

  it('brings an active cluster to the front and toward the centre', () => {
    const sim = createSim({ nodes: ring(10), links: chain(10), seed: 11 }, { jitter: 0 });
    run(sim, 6);
    const before = sim.project(6).nodes.find((p) => p.id === 'c7')!;
    run(sim, 8, { c7: 1 });
    const f = sim.project(14);
    const active = f.nodes.find((p) => p.id === 'c7')!;
    const others = f.nodes.filter((p) => p.id !== 'c7');
    const meanDepth = others.reduce((s, p) => s + p.depth, 0) / others.length;
    expect(active.depth).toBeGreaterThan(meanDepth);
    expect(active.depth).toBeGreaterThan(before.depth);
    expect(Math.hypot(active.x, active.y)).toBeLessThan(0.5);
    // and it is painted last (nearest)
    expect(f.nodes[f.order[f.order.length - 1]!]!.id).toBe('c7');
  });

  it('"front" holds while the camera orbits', () => {
    const sim = createSim({ nodes: ring(10), links: chain(10), seed: 5 }, { jitter: 0 });
    // The sim keeps running while the camera orbits — a quarter turn is 45 s.
    // At each check the active node is still the nearest, i.e. painted last.
    let t = 0;
    for (const seconds of [40, 45, 45]) {
      run(sim, seconds, { c3: 1 });
      t += seconds;
      const f = sim.project(t);
      const nearest = f.nodes[f.order[f.order.length - 1]!]!;
      expect(nearest.id).toBe('c3');
    }
  });

  it('the camera orbit moves the projection; orbit 0 does not', () => {
    const still = createSim({ nodes: ring(6), links: chain(6) }, { jitter: 0, orbit: 0 });
    run(still, 3);
    expect(still.project(3)).toEqual(still.project(60));
    const moving = createSim({ nodes: ring(6), links: chain(6) }, { jitter: 0 });
    run(moving, 3);
    const a = moving.project(3).nodes[0]!;
    const b = moving.project(60).nodes[0]!;
    expect(Math.abs(a.x - b.x) + Math.abs(a.depth - b.depth)).toBeGreaterThan(0.05);
  });

  it('linked clusters end closer together than unlinked ones', () => {
    const nodes = ring(6);
    const sim = createSim({ nodes, links: [{ a: 'c0', b: 'c1', weight: 3 }], seed: 2 }, { jitter: 0 });
    run(sim, 20);
    const f = sim.project(20);
    const p = (id: string) => f.nodes.find((n) => n.id === id)!;
    const d = (a: string, b: string) => Math.hypot(p(a).x - p(b).x, p(a).y - p(b).y);
    expect(d('c0', 'c1')).toBeLessThan(d('c0', 'c3'));
  });

  it('positions() round-trips into a new sim via `at`, so a rebuild starts where the last one left off', () => {
    const a = createSim({ nodes: ring(6), links: chain(6), seed: 4 }, { jitter: 0 });
    run(a, 10);
    const carried = a.positions();
    const b = createSim({ nodes: ring(6).map((n) => ({ ...n, at: carried[n.id] })), links: chain(6), seed: 4 }, { jitter: 0 });
    expect(b.project(10)).toEqual(a.project(10));
  });

  it('keeps the centre of mass on the axis under sustained activity — the cloud does not walk off screen', () => {
    const sim = createSim({ nodes: ring(12), links: chain(12), seed: 9 });
    run(sim, 90, { c2: 1, c7: 0.8, c11: 0.6 });
    const f = sim.project(90);
    const cx = f.nodes.reduce((a, p) => a + p.x, 0) / f.nodes.length;
    const cy = f.nodes.reduce((a, p) => a + p.y, 0) / f.nodes.length;
    expect(Math.abs(cx)).toBeLessThan(0.2);
    expect(Math.abs(cy)).toBeLessThan(0.2);
  });

  it('moves smoothly once settled — no per-frame shake from the boundary or the centring', () => {
    const sim = createSim({ nodes: ring(48), links: chain(48), seed: 21 });
    run(sim, 40, { c3: 1, c20: 0.7 });
    let prev = sim.project(40);
    let worst = 0;
    for (let k = 1; k <= 60; k++) {
      sim.step(1 / 60, { c3: 1, c20: 0.7 });
      const cur = sim.project(40 + k / 60);
      for (let i = 0; i < cur.nodes.length; i++) {
        const a = prev.nodes[i]!;
        const b = cur.nodes[i]!;
        worst = Math.max(worst, Math.hypot(b.x - a.x, b.y - a.y));
      }
      prev = cur;
    }
    // In projected units (the short axis is 2), a frame at 60 fps moves a hub
    // by well under a hundredth: the orbit alone is ~0.0006/frame.
    expect(worst).toBeLessThan(0.01);
  });

  it('drops links to unknown ids and self-links', () => {
    const sim = createSim({ nodes: ring(3), links: [{ a: 'c0', b: 'zzz', weight: 1 }, { a: 'c1', b: 'c1', weight: 1 }, { a: 'c0', b: 'c2', weight: 1 }] });
    expect(sim.project(0).links).toEqual([{ a: 0, b: 2, weight: 1 }]);
  });

  it('a long hidden-tab frame is capped rather than flinging the cloud', () => {
    const sim = createSim({ nodes: ring(8), links: chain(8) });
    run(sim, 2);
    sim.step(600, {}); // ten minutes in one frame
    const f = sim.project(602);
    for (const p of f.nodes) expect(Number.isFinite(p.x) && Math.abs(p.x) < 3).toBe(true);
  });
});
