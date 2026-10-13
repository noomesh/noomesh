// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

/**
 * Force-directed layout for the knowledge graph, computed synchronously.
 *
 * Hand-rolled rather than pulling in d3-force: the whole simulation is ~60
 * lines, and this package is also consumed under React Native, where a
 * DOM-flavoured layout dependency is a liability.
 *
 * The layout is **deterministic** — seeded placement, fixed iteration count —
 * so the same graph draws the same way on every refetch instead of scrambling
 * itself every 30s.
 */

export interface LayoutNode {
  id: string;
  name: string;
  type: string;
  degree: number;
  x: number;
  y: number;
}

export interface LayoutEdge {
  src: string;
  dst: string;
  relType: string;
}

export interface GraphInput {
  nodes: { id: string; name: string; type: string; degree: number }[];
  edges: LayoutEdge[];
}

export interface LayoutResult {
  nodes: LayoutNode[];
  /** Edges whose endpoints both exist, resolved to positions. */
  edges: (LayoutEdge & { x1: number; y1: number; x2: number; y2: number })[];
  width: number;
  height: number;
}

/** mulberry32 — small, fast, and seeded, so placement is reproducible. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const WIDTH = 1000;
const HEIGHT = 620;
const ITERATIONS = 320;

/**
 * Fruchterman-Reingold with a cooling schedule: edges pull, every pair pushes,
 * and the max displacement per step shrinks so the graph settles instead of
 * oscillating.
 */
export function layoutGraph(input: GraphInput): LayoutResult {
  const nodes: LayoutNode[] = input.nodes.map((n, i) => {
    const r = rng(i * 2654435761 + 1);
    // Seed on a spiral rather than uniformly at random: fewer coincident
    // starting points, so the simulation converges in fewer iterations.
    const angle = i * 2.399963;
    const radius = (Math.sqrt(i + 1) / Math.sqrt(input.nodes.length + 1)) * (Math.min(WIDTH, HEIGHT) / 2.4);
    return {
      id: n.id,
      name: n.name,
      type: n.type,
      degree: n.degree,
      x: WIDTH / 2 + Math.cos(angle) * radius + (r() - 0.5) * 8,
      y: HEIGHT / 2 + Math.sin(angle) * radius + (r() - 0.5) * 8,
    };
  });

  const index = new Map(nodes.map((n, i) => [n.id, i]));
  // Drop edges pointing at nodes outside the returned window — the endpoint
  // exists in the graph, just not in this page of it.
  const edges = input.edges.filter((e) => index.has(e.src) && index.has(e.dst));

  const n = nodes.length;
  if (n === 0) return { nodes, edges: [], width: WIDTH, height: HEIGHT };

  const area = WIDTH * HEIGHT;
  const k = Math.sqrt(area / n); // ideal edge length
  const dx = new Float64Array(n);
  const dy = new Float64Array(n);

  for (let iter = 0; iter < ITERATIONS; iter++) {
    dx.fill(0);
    dy.fill(0);

    // Repulsion: every pair pushes apart, k^2 / d.
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let vx = nodes[i]!.x - nodes[j]!.x;
        let vy = nodes[i]!.y - nodes[j]!.y;
        let d2 = vx * vx + vy * vy;
        if (d2 < 0.01) {
          // Coincident: nudge deterministically so the force is defined.
          vx = (i % 7) - 3 + 0.5;
          vy = (j % 7) - 3 + 0.5;
          d2 = vx * vx + vy * vy;
        }
        const d = Math.sqrt(d2);
        const f = (k * k) / d;
        const ux = (vx / d) * f;
        const uy = (vy / d) * f;
        dx[i]! += ux;
        dy[i]! += uy;
        dx[j]! -= ux;
        dy[j]! -= uy;
      }
    }

    // Attraction along edges: d^2 / k.
    for (const e of edges) {
      const i = index.get(e.src)!;
      const j = index.get(e.dst)!;
      const vx = nodes[i]!.x - nodes[j]!.x;
      const vy = nodes[i]!.y - nodes[j]!.y;
      const d = Math.sqrt(vx * vx + vy * vy) || 0.01;
      const f = (d * d) / k;
      const ux = (vx / d) * f;
      const uy = (vy / d) * f;
      dx[i]! -= ux;
      dy[i]! -= uy;
      dx[j]! += ux;
      dy[j]! += uy;
    }

    // Cool: cap displacement, shrinking toward zero.
    const temp = (1 - iter / ITERATIONS) * (Math.min(WIDTH, HEIGHT) / 10);
    for (let i = 0; i < n; i++) {
      const d = Math.sqrt(dx[i]! * dx[i]! + dy[i]! * dy[i]!) || 1;
      const step = Math.min(d, temp);
      nodes[i]!.x += (dx[i]! / d) * step;
      nodes[i]!.y += (dy[i]! / d) * step;
    }
  }

  fitToViewport(nodes);

  return {
    nodes,
    edges: edges.map((e) => {
      const a = nodes[index.get(e.src)!]!;
      const b = nodes[index.get(e.dst)!]!;
      return { ...e, x1: a.x, y1: a.y, x2: b.x, y2: b.y };
    }),
    width: WIDTH,
    height: HEIGHT,
  };
}

/** Rescale the settled graph to fill the viewport, keeping aspect and margin. */
function fitToViewport(nodes: LayoutNode[]): void {
  const pad = 48;
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const n of nodes) {
    if (n.x < minX) minX = n.x;
    if (n.x > maxX) maxX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.y > maxY) maxY = n.y;
  }
  const spanX = maxX - minX || 1;
  const spanY = maxY - minY || 1;
  // One scale for both axes — independent scaling would shear the graph and
  // misrepresent which nodes are actually close together.
  const scale = Math.min((WIDTH - pad * 2) / spanX, (HEIGHT - pad * 2) / spanY);
  const offX = (WIDTH - spanX * scale) / 2;
  const offY = (HEIGHT - spanY * scale) / 2;
  for (const n of nodes) {
    n.x = (n.x - minX) * scale + offX;
    n.y = (n.y - minY) * scale + offY;
  }
}

/** Node radius from degree — sqrt so a 100-edge hub doesn't dwarf everything. */
export function radiusFor(degree: number, maxDegree: number): number {
  const t = maxDegree > 0 ? Math.sqrt(degree) / Math.sqrt(maxDegree) : 0;
  return 4 + t * 13;
}

/**
 * Stable colour per entity type, from the Slate accent ramp. Hash the name so
 * a type keeps its colour across refetches even as counts reorder.
 */
export function colorFor(type: string): string {
  const PALETTE = [
    '#5f8fd0',
    '#5aa66e',
    '#3f9fb0',
    '#9a7bc8',
    '#e0a24a',
    '#c77b7b',
    '#7b9ac7',
    '#8fae5a',
  ];
  let h = 0;
  for (let i = 0; i < type.length; i++) h = (h * 31 + type.charCodeAt(i)) >>> 0;
  return PALETTE[h % PALETTE.length]!;
}
