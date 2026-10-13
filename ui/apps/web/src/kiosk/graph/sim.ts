// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// A small 3-D force simulation with an orbiting camera — the graph view's
// motion model. Pure: no DOM, no canvas, deterministic for a seed, so it can
// be tested with plain numbers.
//
// What the motion means (this is the point, not decoration):
//   - The cloud is never still. Springs on links, repulsion between nodes,
//     a weak pull to the centre, and a little seeded jitter, so the graph
//     morphs slowly rather than freezing into a diagram.
//   - The camera orbits the cloud — one revolution every ~3 minutes, with a
//     gentle tilt wobble — so the whole graph rotates.
//   - Activity brings a node to the front. An entity an ingest just linked is
//     pulled toward the camera and toward the axis, so it comes forward and
//     centres itself; as the activity decays it drifts back into the cloud.
//     "Front" is a camera-space notion, so it holds while the camera moves.
//   - Depth is rendered: near is larger and brighter, far recedes. The
//     projection carries a 0..1 depth per node for the painter.
//
// Units: world positions live in roughly a unit sphere; the painter scales to
// the canvas. Time is seconds.

export interface SimInput {
  /** `x0`/`y0` in [-1, 1] seed a fresh cloud; `at` (world units) carries a position over from a previous sim. */
  nodes: { id: string; mass: number; x0: number; y0: number; at?: { x: number; y: number; z: number } }[];
  links: { a: string; b: string; weight: number }[];
  seed?: number;
}

export interface SimOptions {
  /** Camera angular speed, rad/s. 0 = no orbit. */
  orbit: number;
  /** Jitter amplitude; 0 = no Brownian motion. */
  jitter: number;
}

export const DEFAULTS: SimOptions = {
  orbit: (2 * Math.PI) / 180, // one revolution per 3 minutes
  jitter: 0.18,
};

export interface Projected {
  id: string;
  /** Screen-space in [-1, 1] on the shorter axis; the painter maps to pixels. */
  x: number;
  y: number;
  /** 0 = farthest, 1 = nearest. */
  depth: number;
  /** Perspective scale factor (1 at the axis). */
  scale: number;
  act: number;
  mass: number;
}

export interface Frame {
  nodes: Projected[];
  /** Indices into `nodes`, painted back to front. */
  order: number[];
  links: { a: number; b: number; weight: number }[];
}

interface Body {
  id: string;
  x: number;
  y: number;
  z: number;
  vx: number;
  vy: number;
  vz: number;
  mass: number;
}

/** mulberry32 — seeded, so two displays with the same graph move the same way. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const CAMERA_DIST = 4.4;
const FOCAL = 2.9;
const TILT = 0.32; // ~18°
const WOBBLE = 0.1; // ±6°
const BOUND = 1.7;
/** Where activity pulls a node to: out in front of the cloud, on the camera's line of sight. */
const FRONT = 1.6;

export interface Sim {
  /** Advance by dt seconds. `activity` is id → 0..1, the recency of an ingest. */
  step(dt: number, activity: Record<string, number>): void;
  /** Project the current state for time t (seconds) — the camera is a function of t. */
  project(t: number): Frame;
  /** Update masses in place (an ingest changes counts; structure is unchanged). */
  setMass(id: string, mass: number): void;
  /** Current world positions, so a rebuilt sim (a node appeared) can start where this one left off. */
  positions(): Record<string, { x: number; y: number; z: number }>;
  readonly size: number;
}

export function createSim(input: SimInput, opts: Partial<SimOptions> = {}): Sim {
  const o = { ...DEFAULTS, ...opts };
  const rand = rng(input.seed ?? 7);
  const maxMass = Math.max(1, ...input.nodes.map((n) => n.mass));

  // Seed from a 2-D layout (x0, y0 in [-1, 1]) and spread z deterministically,
  // so the first frame is already a graph and not a point.
  const bodies: Body[] = input.nodes.map((n, i) => ({
    id: n.id,
    x: n.at ? n.at.x : n.x0 * 0.85,
    y: n.at ? n.at.y : n.y0 * 0.85,
    z: n.at ? n.at.z : (rand() - 0.5) * 0.9 + Math.sin(i * 1.7) * 0.15,
    vx: 0,
    vy: 0,
    vz: 0,
    mass: n.mass,
  }));
  const index = new Map(bodies.map((b, i) => [b.id, i]));
  const links = input.links
    .filter((l) => index.has(l.a) && index.has(l.b) && l.a !== l.b)
    .map((l) => ({ a: index.get(l.a)!, b: index.get(l.b)!, weight: l.weight }));
  const maxW = Math.max(1, ...links.map((l) => l.weight));
  const n = bodies.length;
  const act = new Float64Array(n);

  // Camera basis for time t. The camera orbits about the world Y axis, tilted
  // down by TILT with a slow wobble; `dir` is the unit vector from the origin
  // toward the camera, in world space — what "toward the viewer" means.
  function camera(t: number) {
    const theta = t * o.orbit;
    // No orbit means no motion at all (reduced-motion): the wobble goes too.
    const phi = TILT + (o.orbit > 0 ? Math.sin(t * 0.16) * WOBBLE : 0);
    const ct = Math.cos(theta);
    const st = Math.sin(theta);
    const cp = Math.cos(phi);
    const sp = Math.sin(phi);
    // Rotate world → camera: first about Y by -theta, then about X by -phi.
    const toCam = (x: number, y: number, z: number) => {
      const x1 = x * ct - z * st;
      const z1 = x * st + z * ct;
      const y2 = y * cp - z1 * sp;
      const z2 = y * sp + z1 * cp;
      return { x: x1, y: y2, z: z2 };
    };
    // Camera direction in world space: the inverse of `toCam` applied to
    // (0, 0, 1). Undo the X tilt (y2 = y·cp − z·sp, z2 = y·sp + z·cp ⇒ the
    // preimage of (0, 1) is (sp, cp)), then undo the Y orbit.
    const dz = { x: 0, y: sp, z: cp };
    const dir = { x: dz.x * ct + dz.z * st, y: dz.y, z: -dz.x * st + dz.z * ct };
    return { toCam, dir };
  }

  let clock = 0;

  function step(dt: number, activity: Record<string, number>) {
    // Substep for stability; cap a long frame so a tab that was hidden does
    // not fling the cloud apart when it comes back.
    const total = Math.min(dt, 0.1);
    const sub = Math.ceil(total / 0.02);
    const h = total / sub;
    for (let i = 0; i < n; i++) act[i] = Math.max(0, Math.min(1, activity[bodies[i]!.id] ?? 0));
    const { dir } = camera(clock);

    for (let s = 0; s < sub; s++) {
      const fx = new Float64Array(n);
      const fy = new Float64Array(n);
      const fz = new Float64Array(n);

      // Repulsion, every pair. Heavier nodes push a little harder, so the
      // big ones claim room.
      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
          const a = bodies[i]!;
          const b = bodies[j]!;
          let dx = a.x - b.x;
          let dy = a.y - b.y;
          let dz = a.z - b.z;
          let d2 = dx * dx + dy * dy + dz * dz;
          if (d2 < 1e-4) {
            dx = (i % 3) - 1 + 0.01;
            dy = (j % 3) - 1 + 0.02;
            dz = 0.03;
            d2 = dx * dx + dy * dy + dz * dz;
          }
          const d = Math.sqrt(d2);
          const m = 1 + 0.5 * ((a.mass + b.mass) / (2 * maxMass));
          const f = Math.min(9, (0.5 * m) / d2);
          const ux = (dx / d) * f;
          const uy = (dy / d) * f;
          const uz = (dz / d) * f;
          fx[i]! += ux;
          fy[i]! += uy;
          fz[i]! += uz;
          fx[j]! -= ux;
          fy[j]! -= uy;
          fz[j]! -= uz;
        }
      }

      // Springs on links: heavier links want to be shorter.
      for (const l of links) {
        const a = bodies[l.a]!;
        const b = bodies[l.b]!;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dz = b.z - a.z;
        const d = Math.sqrt(dx * dx + dy * dy + dz * dz) || 1e-3;
        const w = l.weight / maxW;
        const rest = 1.0 - 0.35 * w;
        const f = 1.1 * (d - rest);
        const ux = (dx / d) * f;
        const uy = (dy / d) * f;
        const uz = (dz / d) * f;
        fx[l.a]! += ux;
        fy[l.a]! += uy;
        fz[l.a]! += uz;
        fx[l.b]! -= ux;
        fy[l.b]! -= uy;
        fz[l.b]! -= uz;
      }

      for (let i = 0; i < n; i++) {
        const b = bodies[i]!;
        // Weak gravity to the centre keeps the cloud a cloud — weak, so the
        // repulsion wins and the cloud is a cloud rather than a ball.
        fx[i]! -= b.x * 0.12;
        fy[i]! -= b.y * 0.12;
        fz[i]! -= b.z * 0.12;
        // The boundary is a spring, not a wall. A hard clamp put every hub the
        // repulsion pushed to the edge exactly on the edge, where the centroid
        // correction nudged it off and the next step clamped it back — a
        // per-frame oscillation on every body at the boundary. An active hub
        // may stand a little outside; that is what being in front means.
        {
          const lim = BOUND + 0.25 * act[i]!;
          const r = Math.sqrt(b.x * b.x + b.y * b.y + b.z * b.z);
          if (r > lim) {
            const k = (6 * (r - lim)) / r;
            fx[i]! -= b.x * k;
            fy[i]! -= b.y * k;
            fz[i]! -= b.z * k;
          }
        }
        // Activity: toward a point out in front of the cloud on the camera's
        // line of sight. Camera-space, so "front" survives the orbit.
        const a = act[i]!;
        if (a > 0) {
          const tx = dir.x * FRONT;
          const ty = dir.y * FRONT;
          const tz = dir.z * FRONT;
          const k = 10 * a;
          fx[i]! += (tx - b.x) * k;
          fy[i]! += (ty - b.y) * k;
          fz[i]! += (tz - b.z) * k;
        }
        // Jitter: the graph breathes on its own.
        if (o.jitter > 0) {
          fx[i]! += (rand() - 0.5) * o.jitter;
          fy[i]! += (rand() - 0.5) * o.jitter;
          fz[i]! += (rand() - 0.5) * o.jitter;
        }
        // Integrate with damping; heavier bodies move a bit more slowly.
        const inv = 1 / (0.7 + 0.6 * (b.mass / maxMass));
        b.vx = (b.vx + fx[i]! * inv * h) * 0.88;
        b.vy = (b.vy + fy[i]! * inv * h) * 0.88;
        b.vz = (b.vz + fz[i]! * inv * h) * 0.88;
        b.x += b.vx * h;
        b.y += b.vy * h;
        b.z += b.vz * h;
      }
    }
    // Keep the cloud's centre of mass on the axis. The activity pull drags
    // hubs toward a point on the camera's line of sight (which has a vertical
    // component from the tilt), and the springs drag their neighbours after
    // them; without this the cloud slowly walks off centre. Every body shifts
    // by the same amount, so nothing jerks, and an active hub is still on the
    // line of sight — that line passes through the origin.
    let cx = 0;
    let cy = 0;
    let cz = 0;
    let mt = 0;
    for (const b of bodies) {
      cx += b.x * b.mass;
      cy += b.y * b.mass;
      cz += b.z * b.mass;
      mt += b.mass;
    }
    // Gradually — a fraction per frame — so it is a drift back to centre,
    // never a per-frame jump the eye can read as shake.
    if (mt > 0) {
      const g = Math.min(1, 1.5 * total);
      cx = (cx / mt) * g;
      cy = (cy / mt) * g;
      cz = (cz / mt) * g;
      for (const b of bodies) {
        b.x -= cx;
        b.y -= cy;
        b.z -= cz;
      }
    }
    clock += total;
  }

  function project(t: number): Frame {
    const { toCam } = camera(t);
    const nodes: Projected[] = bodies.map((b, i) => {
      const c = toCam(b.x, b.y, b.z);
      const scale = FOCAL / (CAMERA_DIST - c.z);
      return {
        id: b.id,
        x: c.x * scale,
        y: c.y * scale,
        depth: Math.max(0, Math.min(1, (c.z + BOUND) / (2 * BOUND))),
        scale,
        act: act[i]!,
        mass: b.mass,
      };
    });
    const order = nodes.map((_, i) => i).sort((i, j) => nodes[i]!.depth - nodes[j]!.depth);
    return { nodes, order, links };
  }

  return {
    step,
    project,
    setMass(id, mass) {
      const i = index.get(id);
      if (i != null) bodies[i]!.mass = mass;
    },
    positions() {
      return Object.fromEntries(bodies.map((b) => [b.id, { x: b.x, y: b.y, z: b.z }]));
    },
    get size() {
      return n;
    },
  };
}
