// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Particles that travel along links — what makes the links look like they
// carry something. Two kinds: a burst *into* a cluster when an ingest grows
// it (the visible meaning of "written to"), and a faint ambient trickle so
// the graph reads as alive between ingests. Pure; the painter positions them
// by interpolating the projected endpoints each frame.

export interface Particle {
  /** Index into the frame's links. */
  link: number;
  /** Travel from link.a toward link.b when true, else the reverse. */
  forward: boolean;
  /** 0..1 along the link. */
  t: number;
  speed: number;
  size: number;
  /** 1 for an ingest burst, lower for the ambient trickle. */
  intensity: number;
}

export interface ParticleField {
  readonly items: readonly Particle[];
  /** Spawn a burst along every link touching node `into`, travelling toward it. */
  burst(into: number, links: readonly { a: number; b: number }[], count: number): void;
  /** One faint ambient particle on a pseudo-random link. */
  trickle(linkCount: number): void;
  step(dt: number): void;
}

export function createParticles(seed = 1): ParticleField {
  let s = seed >>> 0;
  const rand = () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  let items: Particle[] = [];
  return {
    get items() {
      return items;
    },
    burst(into, links, count) {
      links.forEach((l, i) => {
        if (l.a !== into && l.b !== into) return;
        for (let k = 0; k < count; k++) {
          items.push({
            link: i,
            forward: l.b === into,
            t: -rand() * 0.6, // stagger the start so they stream, not march
            speed: 0.45 + rand() * 0.35,
            size: 1.6 + rand() * 1.8,
            intensity: 1,
          });
        }
      });
    },
    trickle(linkCount) {
      if (linkCount === 0) return;
      items.push({
        link: Math.floor(rand() * linkCount) % linkCount,
        forward: rand() < 0.5,
        t: 0,
        speed: 0.24 + rand() * 0.22,
        size: 0.9 + rand() * 0.8,
        intensity: 0.35,
      });
    },
    step(dt) {
      for (const p of items) p.t += p.speed * dt;
      items = items.filter((p) => p.t <= 1);
    },
  };
}
