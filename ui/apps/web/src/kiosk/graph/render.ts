// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The painter. Takes a projected frame and draws it on a 2-D canvas as a
// dense, organic hologram with depth of field: warm glass hubs on cool
// fibres. Each entity is a translucent sphere with its connections orbiting it
// as dust — thousands of points from the counts alone, never a name — with
// dendrites back to the hub; links between entities are bundles of swept
// filaments with particles travelling along them; small monospace tags sit
// on the hubs that matter. Two layers: what is far is drawn blurred, what is
// near is drawn sharp, so the eye is told where to look. A camera focus
// (pan + zoom, driven by the view) pushes in on an active area now and then.
//
// Palette, from the Noomesh tokens and nothing else: the brand blue
// (#5F8FD0) for every fibre; hubs in a tan pulled from the `warn` amber and
// a dusty rose pulled from the `bad` coral — both desaturated well away from
// their alarm meanings — and a minority in the blue. Activity brightens a
// hub, brings it forward, sends particles in, lends one warm strand to each
// of its fibre bundles, and adds the one saturated mark: an amber pulse
// ring. Green and red are never used; they mean things elsewhere.

import type { Frame, Projected } from './sim';
import type { Particle } from './particles';
import type { Quality } from './quality';

export interface Focus {
  /** Projected-space point the camera is centred on (0,0 = the cloud's axis). */
  x: number;
  y: number;
  /** 1 = the whole cloud; >1 pushes in. */
  zoom: number;
  /** 0..1, how strong the depth-of-field blur is. */
  dof: number;
}

export interface PaintOptions {
  width: number;
  height: number;
  dpr: number;
  labels: boolean;
  names: Record<string, string>;
  /** Extra tag lines per hub id (e.g. when it last grew). */
  tags: Record<string, string[]>;
  /** Seconds — drives the satellites' orbits and the pulse rings. */
  t: number;
  maxMass: number;
  particles: readonly Particle[];
  readout: { entities: number | null; links: number | null; linksDrawn: number | null; growing: number };
  focus: Focus;
  /**
   * Drawing tier for a machine that cannot keep up (see graph/quality.ts).
   * `lean`: no blurred far layer, no bokeh, no per-hub glow or specular —
   * the passes that dominate in software rendering. `flat`: solid hubs,
   * one straight stroke per link, no dendrites, particles or tags — the
   * picture and nothing else. Both put a line in the readout saying so.
   */
  tier?: Quality;
}

const hsla = (h: number, s: number, l: number, a: number) => `hsla(${h} ${s}% ${l}% / ${a})`;
const BLUE = 214;
const AMBER = { h: 36, s: 72, l: 60 };
const amber = (a: number, dl = 0) => hsla(AMBER.h, AMBER.s, AMBER.l + dl, a);

type Family = 'tan' | 'rose' | 'blue';
function familyOf(id: string): Family {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  const r = h % 8;
  return r < 4 ? 'tan' : r < 6 ? 'rose' : 'blue';
}
/**
 * The three noise values each dust mote needs, computed once per hub.
 *
 * They are a pure function of (entity id, dot index) and never change, yet
 * they were being recomputed every frame for every mote: up to 160 hubs x
 * 70 motes x 3 hashes, and each hash walks the whole id — which is a UUID.
 * That is on the order of a million multiply-xor operations per frame to
 * re-derive constants, on a machine chosen for being quiet rather than
 * fast. Float64, not Float32: at 32 bits the cached value differs from
 * recomputing in the eighth decimal, which no one could see — but then
 * "identical output" would be a claim the guard could not make, and a
 * quarter of a megabyte is not worth buying a weaker guarantee with.
 */
const dotCache = new Map<string, Float64Array>();

/** Bounded: a wall display runs for weeks and entities come and go. */
const DOT_CACHE_MAX = 512;

export function dotNoise(id: string, count: number): Float64Array {
  const have = dotCache.get(id);
  if (have && have.length >= count * 3) return have;
  // A hub that gains degree needs more motes than last time. Extend rather
  // than replace, so the ones already on screen keep their places.
  const out = new Float64Array(count * 3);
  if (have) out.set(have);
  for (let k = have ? have.length / 3 : 0; k < count; k++) {
    out[k * 3] = noise(id, k);
    out[k * 3 + 1] = noise(id, k + 1000);
    out[k * 3 + 2] = noise(id, k + 2000);
  }
  if (dotCache.size >= DOT_CACHE_MAX) dotCache.clear();
  dotCache.set(id, out);
  return out;
}

/** For the guard that keeps the cache bounded. */
export function dotCacheSize(): number {
  return dotCache.size;
}

function hubTone(f: Family, near: number, act: number) {
  const base = f === 'tan' ? { h: 32, s: 40, l: 66 } : f === 'rose' ? { h: 354, s: 32, l: 68 } : { h: BLUE, s: 52, l: 66 };
  return { h: base.h, s: base.s + 8 * act, l: base.l - 14 * (1 - near) + 8 * act };
}
const fibre = (near: number, a: number, dl = 0) => hsla(BLUE - 10, 64, 68 + dl - 10 * (1 - near), a);
const warmStrand = (near: number, a: number) => hsla(32, 60, 66 - 8 * (1 - near), a);

/** A cheap seeded number per (id, k), for satellite and bokeh placement. */
export function noise(id: string, k: number): number {
  let h = 2166136261 ^ k;
  for (let i = 0; i < id.length; i++) h = Math.imul(h ^ id.charCodeAt(i), 16777619);
  h = Math.imul(h ^ (h >>> 13), 1274126177);
  return ((h ^ (h >>> 16)) >>> 0) / 4294967296;
}

/** Quadratic control for a fibre: swept toward the canvas centre, fanned per strand. */
function control(ax: number, ay: number, bx: number, by: number, cx: number, cy: number, bend: number, fan: number) {
  const mx = (ax + bx) / 2;
  const my = (ay + by) / 2;
  const dx = bx - ax;
  const dy = by - ay;
  const len = Math.hypot(dx, dy) || 1;
  return { x: mx + (cx - mx) * bend + (-dy / len) * fan * len * 0.07, y: my + (cy - my) * bend + (dx / len) * fan * len * 0.07 };
}
const q = (a: number, c: number, b: number, t: number) => (1 - t) * (1 - t) * a + 2 * (1 - t) * t * c + t * t * b;

// One offscreen canvas for the blurred far layer, reused across frames.
let far: HTMLCanvasElement | null = null;
function farCanvas(w: number, h: number): CanvasRenderingContext2D | null {
  if (typeof document === 'undefined') return null;
  if (!far) far = document.createElement('canvas');
  if (far.width !== w || far.height !== h) {
    far.width = w;
    far.height = h;
  }
  return far.getContext('2d');
}

type Layer = 'far' | 'near';
const SPLIT = 0.5;

export function paint(ctx: CanvasRenderingContext2D, frame: Frame, o: PaintOptions): void {
  const tier = o.tier ?? 'full';
  const flat = tier === 'flat';
  const full = tier === 'full';
  const { width: W, height: H, dpr } = o;
  ctx.save();
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);

  // ── Ground ──────────────────────────────────────────────────────────────
  const g = ctx.createRadialGradient(W * 0.5, H * 0.45, 0, W * 0.5, H * 0.45, Math.max(W, H) * 0.75);
  g.addColorStop(0, '#0c0f16');
  g.addColorStop(0.6, '#080a0f');
  g.addColorStop(1, '#04050a');
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, W, H);

  // ── Camera: projected space → pixels, with the focus applied ───────────
  const S = Math.min(W * 0.42, H * 0.52) * o.focus.zoom;
  // Constant for the frame, and it was recomputed per mote and per particle:
  // tens of thousands of square roots for one number.
  const zoomScale = Math.sqrt(o.focus.zoom);
  const CX = W / 2;
  const CY = H / 2;
  const px = (p: Projected) => ({ x: CX + (p.x - o.focus.x) * S, y: CY + (p.y - o.focus.y) * S });
  const pos = frame.nodes.map(px);
  const hubR = (p: Projected) =>
    Math.min(W, H) * (0.0045 + 0.017 * Math.sqrt(p.mass / o.maxMass)) * (0.6 + 0.6 * p.scale) * (1 + 0.15 * p.act) * zoomScale;
  const nearOf = (p: Projected) => 0.25 + 0.75 * p.depth;
  const maxW = Math.max(1, ...frame.links.map((l) => l.weight));

  // The far layer goes to the offscreen canvas at half resolution and comes
  // back blurred; the near layer is painted straight on. Bokeh, cheaply.
  const fctx = farCanvas(Math.ceil(W / 2), Math.ceil(H / 2));
  const drawLayer = (c: CanvasRenderingContext2D, layer: Layer, scale: number) => {
    c.save();
    c.setTransform(scale, 0, 0, scale, 0, 0);
    c.globalCompositeOperation = 'lighter';
    c.lineCap = 'round';
    const inLayer = (depth: number) => (layer === 'far' ? depth < SPLIT : depth >= SPLIT);

    // Background bokeh — soft discs at the back of the room, only in the far layer.
    if (layer === 'far' && full) {
      for (let k = 0; k < 42; k++) {
        const bx = (noise('bokeh', k) + o.t * 0.004 * (noise('bokeh', k + 500) - 0.5)) % 1;
        const by = noise('bokeh', k + 1000);
        const x = ((bx + 1) % 1) * W;
        const y = by * H;
        const r = 4 + noise('bokeh', k + 2000) * 14;
        const warm = noise('bokeh', k + 3000) < 0.3;
        const gr = c.createRadialGradient(x, y, 0, x, y, r);
        gr.addColorStop(0, warm ? amber(0.16, 6) : hsla(BLUE, 55, 68, 0.14));
        gr.addColorStop(1, warm ? amber(0) : hsla(BLUE, 55, 68, 0));
        c.fillStyle = gr;
        c.beginPath();
        c.arc(x, y, r, 0, Math.PI * 2);
        c.fill();
      }
    }

    // Fibres: bundles of swept strands. One strand goes warm where data flows.
    for (const l of frame.links) {
      const a = frame.nodes[l.a]!;
      const b = frame.nodes[l.b]!;
      const depth = (a.depth + b.depth) / 2;
      if (!inLayer(depth)) continue;
      const pa = pos[l.a]!;
      const pb = pos[l.b]!;
      const w = l.weight / maxW;
      const act = Math.max(a.act, b.act);
      if (flat) {
        c.strokeStyle = hsla(BLUE, 40, 70, (0.12 + 0.25 * depth) * (0.6 + 0.4 * w) + 0.3 * act);
        c.lineWidth = 0.6 + 0.5 * depth;
        c.beginPath();
        c.moveTo(pa.x, pa.y);
        c.lineTo(pb.x, pb.y);
        c.stroke();
        continue;
      }
      const strands = 3 + Math.round(w * 4);
      const bend = 0.18 + 0.12 * noise(`${l.a}-${l.b}`, 1);
      for (let k = 0; k < strands; k++) {
        const fan = (k - (strands - 1) / 2) * 0.8;
        const cp = control(pa.x, pa.y, pb.x, pb.y, CX, CY, bend, fan);
        // The warm strand is a moment, not a state: it flares with the ingest
        // (activity squared) and has mostly dissolved within a minute, so the
        // gold never becomes a second network laid over the blue one.
        const warm = act > 0.08 && k === 0;
        c.strokeStyle = warm
          ? warmStrand(depth, (0.08 + 0.3 * act * act) * (0.5 + 0.5 * depth))
          : fibre(depth, (0.05 + 0.15 * depth) * (0.6 + 0.4 * w) * (1 + 0.35 * act), 4);
        c.lineWidth = (warm ? 0.6 : 0.5) + 0.35 * depth;
        c.beginPath();
        c.moveTo(pa.x, pa.y);
        c.quadraticCurveTo(cp.x, cp.y, pb.x, pb.y);
        c.stroke();
      }
    }

    // Particles along the fibres.
    for (const p of o.particles) {
      const l = frame.links[p.link];
      if (!l || p.t < 0) continue;
      const depth = (frame.nodes[l.a]!.depth + frame.nodes[l.b]!.depth) / 2;
      if (!inLayer(depth)) continue;
      const from = pos[p.forward ? l.a : l.b]!;
      const to = pos[p.forward ? l.b : l.a]!;
      const bend = 0.18 + 0.12 * noise(`${l.a}-${l.b}`, 1);
      const cp = control(from.x, from.y, to.x, to.y, CX, CY, bend, 0);
      const e = p.t < 0.5 ? 2 * p.t * p.t : 1 - Math.pow(-2 * p.t + 2, 2) / 2;
      const x = q(from.x, cp.x, to.x, e);
      const y = q(from.y, cp.y, to.y, e);
      const fade = Math.sin(Math.min(1, Math.max(0, p.t)) * Math.PI);
      const hot = p.intensity >= 1;
      const r = p.size * (hot ? 1.1 : 0.7) * zoomScale;
      const gr = c.createRadialGradient(x, y, 0, x, y, r * 4);
      gr.addColorStop(0, hsla(BLUE - 6, 70, 74, (hot ? 0.55 : 0.4) * fade));
      gr.addColorStop(1, hsla(BLUE - 6, 70, 74, 0));
      c.fillStyle = gr;
      c.beginPath();
      c.arc(x, y, r * 4, 0, Math.PI * 2);
      c.fill();
      c.fillStyle = hsla(BLUE, 30, hot ? 98 : 94, (hot ? 1 : 0.85) * fade);
      c.beginPath();
      c.arc(x, y, r, 0, Math.PI * 2);
      c.fill();
    }

    // Hubs, back to front: dust and dendrites, glow, then the glass.
    for (const i of frame.order) {
      const p = frame.nodes[i]!;
      if (!inLayer(p.depth)) continue;
      const { x, y } = pos[i]!;
      const r = hubR(p);
      const near = nearOf(p);
      const tone = hubTone(familyOf(p.id), near, p.act);
      // mass is sqrt(degree), so this recovers the degree: the orbiting
      // dots are the entity's connections.
      const degree = Math.round(p.mass * p.mass);
      const dotCount = flat ? 0 : Math.min(70, degree);
      const field = r * (2.4 + 1.4 * Math.sqrt(dotCount / 70)) * (0.7 + 0.5 * p.scale);

      const seeds = dotNoise(p.id, dotCount);
      for (let k = 0; k < dotCount; k++) {
        const n1 = seeds[k * 3]!;
        const n2 = seeds[k * 3 + 1]!;
        const n3 = seeds[k * 3 + 2]!;
        const inside = n3 < 0.3; // some sit inside the glass
        const ang = n1 * Math.PI * 2 + o.t * (0.03 + 0.05 * n2) * (n3 < 0.5 ? 1 : -1);
        const rad = inside ? r * 0.85 * Math.sqrt(n2) : field * (0.4 + 0.6 * Math.sqrt(n2));
        const tilt = inside ? 1 : 0.5 + 0.5 * n3;
        const sx = x + Math.cos(ang) * rad;
        const sy = y + Math.sin(ang) * rad * tilt;
        const bright = n3 > 0.86;
        const size = (bright ? 1.5 : 0.95) * (0.6 + 0.6 * p.scale) * zoomScale;
        c.fillStyle = bright ? hsla(BLUE, 40, 93, 0.9 * near) : hsla(tone.h, tone.s, tone.l + 8, (0.3 + 0.4 * n1) * near);
        c.fillRect(sx - size / 2, sy - size / 2, size, size);
        if (!inside && k % 4 === 0) {
          c.strokeStyle = fibre(near, 0.07 + 0.1 * p.act, 2);
          c.lineWidth = 0.45;
          c.beginPath();
          c.moveTo(x, y);
          c.quadraticCurveTo(x + (sx - x) * 0.5 + (sy - y) * 0.2, y + (sy - y) * 0.5 - (sx - x) * 0.2, sx, sy);
          c.stroke();
        }
      }

      const gr = r * (3 + 1.6 * p.act);
      if (full) {
        const glow = c.createRadialGradient(x, y, r * 0.5, x, y, gr);
        glow.addColorStop(0, hsla(tone.h, tone.s, tone.l, (0.14 + 0.22 * p.act) * near));
        glow.addColorStop(1, hsla(tone.h, tone.s, tone.l, 0));
        c.fillStyle = glow;
        c.beginPath();
        c.arc(x, y, gr, 0, Math.PI * 2);
        c.fill();
      }

      // Glass: a faint body that brightens toward the rim, a bright rim, a
      // small specular, a dim inner reflection.
      if (flat) {
        c.fillStyle = hsla(tone.h, tone.s, tone.l, 0.28 * near);
        c.beginPath();
        c.arc(x, y, r, 0, Math.PI * 2);
        c.fill();
        c.strokeStyle = hsla(tone.h, tone.s, tone.l + 18, 0.8 * near);
        c.lineWidth = Math.max(0.8, r * 0.07);
        c.beginPath();
        c.arc(x, y, r, 0, Math.PI * 2);
        c.stroke();
      } else {
        const body = c.createRadialGradient(x, y, r * 0.2, x, y, r);
        body.addColorStop(0, hsla(tone.h, tone.s, tone.l, 0.06 * near));
        body.addColorStop(0.78, hsla(tone.h, tone.s, tone.l, 0.16 * near));
        body.addColorStop(1, hsla(tone.h, tone.s, tone.l + 14, 0.55 * near));
        c.fillStyle = body;
        c.beginPath();
        c.arc(x, y, r, 0, Math.PI * 2);
        c.fill();
        c.strokeStyle = hsla(tone.h, tone.s, tone.l + 18, 0.75 * near);
        c.lineWidth = Math.max(0.8, r * 0.07);
        c.beginPath();
        c.arc(x, y, r, 0, Math.PI * 2);
        c.stroke();
        c.strokeStyle = hsla(tone.h, tone.s, tone.l + 10, 0.2 * near);
        c.lineWidth = 0.6;
        c.beginPath();
        c.arc(x + r * 0.12, y + r * 0.12, r * 0.72, Math.PI * 0.15, Math.PI * 0.95);
        c.stroke();
        if (full) {
          const spec = c.createRadialGradient(x - r * 0.42, y - r * 0.45, 0, x - r * 0.42, y - r * 0.45, r * 0.42);
          spec.addColorStop(0, `rgba(255,255,255,${0.75 * near})`);
          spec.addColorStop(1, 'rgba(255,255,255,0)');
          c.fillStyle = spec;
          c.beginPath();
          c.arc(x, y, r, 0, Math.PI * 2);
          c.fill();
        }
        const dot = c.createRadialGradient(x, y, 0, x, y, r * 0.28);
        dot.addColorStop(0, hsla(tone.h, 25, 97, 0.9 * near));
        dot.addColorStop(1, hsla(tone.h, tone.s, tone.l, 0));
        c.fillStyle = dot;
        c.beginPath();
        c.arc(x, y, r * 0.28, 0, Math.PI * 2);
        c.fill();
      }
      if (p.act > 0.03) {
        const a = p.act * near;
        const phase = ((o.t * 0.35 + i * 0.17) % 1 + 1) % 1;
        c.strokeStyle = amber((1 - phase) * 0.55 * a, 8);
        c.lineWidth = 1.3 * (1 - phase) + 0.4;
        c.beginPath();
        c.arc(x, y, r * (1.5 + phase * 3), 0, Math.PI * 2);
        c.stroke();
      }
    }
    c.restore();
  };

  if (fctx && full) {
    fctx.setTransform(1, 0, 0, 1, 0, 0);
    fctx.clearRect(0, 0, fctx.canvas.width, fctx.canvas.height);
    drawLayer(fctx, 'far', 0.5);
    ctx.globalCompositeOperation = 'lighter';
    ctx.filter = `blur(${(1.5 + 4 * o.focus.dof).toFixed(1)}px)`;
    ctx.drawImage(fctx.canvas, 0, 0, W, H);
    ctx.filter = 'none';
    ctx.globalCompositeOperation = 'source-over';
  } else {
    drawLayer(ctx, 'far', dpr);
  }
  drawLayer(ctx, 'near', dpr);

  // ── Tags: metadata blocks on the near hubs that matter ─────────────────
  ctx.globalCompositeOperation = 'source-over';
  const fs = Math.max(9, Math.round(Math.min(W, H) / 80));
  const line = fs * 1.3;
  ctx.font = `500 ${fs}px ui-monospace, "Cascadia Code", Consolas, Menlo, monospace`;
  ctx.textBaseline = 'middle';
  if (!flat) {
  // Tags without names (labels off) only when the camera has pushed in: at
  // wide, forty hubs' worth of text collides into mud; in the push-in there
  // is room. They fade in with the zoom, and those are UUID fragments nobody
  // wants on a wall at a distance. With the names switch ON the tags are the
  // point of the switch, so they are drawn at wide too, at full strength;
  // the cap and the overlap skip below keep the wide view from going to mud.
  // Who gets one is a legible rule: any hub on screen is eligible
  // (no depth cliff — two hubs on the same plane must be treated the same);
  // active hubs first, then the nearest to what the camera is looking at,
  // with nearer-in-depth preferred; the cap is applied after the visibility
  // check; and a tag whose box would overlap one already placed is skipped,
  // so the nearest wins and nothing overlaps.
  const tagA = tagAlpha(o.focus.zoom, o.labels);
  const cap = o.labels ? 7 : 5;
  const onScreen = frame.order.filter((i) => {
    const { x, y } = pos[i]!;
    return x > 0 && x < W && y > 0 && y < H;
  });
  const score = (i: number) => {
    const p = frame.nodes[i]!;
    const d = Math.hypot(pos[i]!.x - CX, pos[i]!.y - CY) / Math.max(1, Math.min(W, H));
    return (p.act > 0.1 ? 0 : 10) + d / (0.4 + 0.6 * p.depth) - p.act;
  };
  const ranked = tagA < 0.02 ? [] : [...onScreen].sort((i, j) => score(i) - score(j));
  const placed: { x0: number; y0: number; x1: number; y1: number }[] = [];
  let shown = 0;
  for (const i of ranked) {
    if (shown >= cap) break;
    const p = frame.nodes[i]!;
    const { x, y } = pos[i]!;
    const r = hubR(p);
    const nr = nearOf(p);
    const rightSide = x < CX;
    const dir = rightSide ? 1 : -1;
    const lx = x + dir * r * 2.6;
    const ly = y - r * 1.9;
    const tx = lx + dir * 14;
    const title = o.labels ? (o.names[p.id] ?? p.id).toUpperCase() : p.id.toUpperCase();
    const rows: [string, string][] = [
      ['CLUSTER', title],
      ['MEMBERS', String(Math.round(p.mass * p.mass))],
      ...(o.tags[p.id] ?? []).map((t) => t.split('=') as [string, string]),
    ];
    // The tag's box, for the overlap test. Width from the widest row.
    const wmax = Math.max(...rows.map(([k, v]) => ctx.measureText(k + '  ' + v).width));
    const box = rightSide
      ? { x0: tx, y0: ly - line * 0.6, x1: tx + wmax, y1: ly + rows.length * line }
      : { x0: tx - wmax, y0: ly - line * 0.6, x1: tx, y1: ly + rows.length * line };
    if (placed.some((q) => box.x0 < q.x1 + 8 && box.x1 > q.x0 - 8 && box.y0 < q.y1 + 4 && box.y1 > q.y0 - 4)) continue;
    placed.push(box);
    shown++;

    ctx.strokeStyle = fibre(nr, 0.4 * tagA);
    ctx.lineWidth = 0.7;
    ctx.beginPath();
    ctx.moveTo(x + dir * r * 0.95, y - r * 0.5);
    ctx.lineTo(lx, ly);
    ctx.lineTo(lx + dir * 10, ly);
    ctx.stroke();
    ctx.textAlign = rightSide ? 'left' : 'right';
    rows.forEach(([k, v], n) => {
      const yy = ly + n * line;
      ctx.fillStyle = p.act > 0.1 ? amber(0.85 * nr * tagA, 6) : `rgba(137,147,166,${0.8 * nr * tagA})`;
      ctx.fillText(k, tx, yy);
      const kw = ctx.measureText(k + '  ').width;
      ctx.fillStyle = `rgba(230,234,241,${(0.55 + 0.45 * p.depth) * nr * tagA})`;
      ctx.fillText(v, tx + dir * kw, yy);
    });
  }

  }
  // ── Corner readouts ─────────────────────────────────────────────────────
  ctx.textAlign = 'left';
  ctx.fillStyle = 'rgba(137,147,166,0.5)';
  const m = Math.min(W, H) * 0.025;
  const orbit = Math.round(((o.t * (360 / 180)) % 360 + 360) % 360);
  [
    `CLUSTERS ${String(frame.nodes.length).padStart(4)}`,
    `ENTITIES ${String(o.readout.entities ?? '—').padStart(4)}`,
    // Drawn/total when the gateway has capped them, so the screen never
    // reports a density it is not showing.
    (() => {
      const { links, linksDrawn } = o.readout;
      const shown =
        links != null && linksDrawn != null && linksDrawn < links
          ? `${linksDrawn}/${links}`
          : String(links ?? '—');
      return `LINKS    ${shown.padStart(4)}`;
    })(),
    `ORBIT    ${String(orbit).padStart(3)}°`,
  ].forEach((s, k) => ctx.fillText(s, m, m + k * line));
  ctx.textAlign = 'right';
  // "LEAN" is the page saying it degraded — the same rule as the health
  // view's strip: the reader can see what they are not being shown.
  rightReadout(o.readout.growing, o.focus.zoom, tier, o.labels).forEach((s, k) =>
    ctx.fillText(s, W - m, m + k * line),
  );
  ctx.restore();
}

/**
 * The top-right readout lines. `LABELS ON` is the controller's names
 * switch, said on the picture itself: the strip can be cropped by a bezel
 * or scrolled past in a screenshot, and the canvas is what gets shared.
 */
/** How strongly hub tags are drawn: 1 whenever names are on, else the push-in fade. */
export function tagAlpha(zoom: number, labels: boolean): number {
  if (labels) return 1;
  return Math.max(0, Math.min(1, (zoom - 1.15) / 0.9));
}

export function rightReadout(growing: number, zoom: number, tier: Quality | undefined, labels: boolean): string[] {
  return [
    `GROWING ${growing}`,
    zoom > 1.05 ? `FOCUS ×${zoom.toFixed(1)}` : 'WIDE',
    'ENTITY VIEW',
    ...(labels ? ['LABELS ON'] : []),
    ...(tier === 'lean' ? ['LEAN · CPU RENDER'] : tier === 'flat' ? ['FLAT · CPU RENDER'] : []),
  ];
}
