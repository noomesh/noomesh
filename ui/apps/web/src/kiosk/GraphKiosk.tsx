// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The graph view — the second kiosk. Not "is the mesh healthy" (that's
// Kiosk.tsx) but "what does this thing know": the knowledge graph as a
// slowly orbiting cloud with depth of field, the entities an ingest just
// connected coming forward and lighting up, and a camera that pushes in on
// an active area now and then, then eases back out.
//
// ENTITY level, not cluster level. This showed clusters and, on the first
// real display, drew 58 nodes and zero links: clustering covered 761 of
// 4,538 entities and inter-cluster edges need two shared entity edges with
// both endpoints already clustered. It could not react to an ingest either,
// because clusters move on a recluster pass. Entities and edges are written
// by every tier on every ingest, so this view is both full and live.
//
// Why no labels by default, and why that matters MORE here: the health
// kiosk shows hostnames; a knowledge graph shows what you *know*. A cluster
// label was an LLM's summary of an area. An entity name is a person, a
// document, a customer — and this is a screen in a hallway. So the gateway
// decides at fetch time: `/api/kiosk/graph` sends no `name` at all unless
// the operator has switched the controller's `kiosk.graph_labels` on
// (`noo kiosk labels on`), and what arrives here without it is a UUID, a
// type and a degree. Nothing to leak, whatever this file does next. While
// it IS on, the strip and the canvas both say `LABELS ON`, so anyone
// standing at the display can see that names are being shown.
//
// Motion is meaning (graph/sim.ts): the camera orbits; activity pulls an
// entity toward the viewer and the axis; particles stream along links into
// an entity when it gains one. The rest of the display rules hold — duration
// is the payload (the strip), never colour alone, degrade visibly, no input.

import { useEffect, useMemo, useRef } from 'react';
import { layoutGraph } from '@/lib/graph/layout';
import { LivenessBand, type Pager } from './Band';
import { graphView, fmtDuration, RECENT_GROWTH_MS, type AddonWord, type GraphView, type KioskState } from './store';
import { createSim, type Sim } from './graph/sim';
import { createGovernor, mayPushIn, smooth, type Quality } from './graph/quality';

declare global {
  interface Window {
    /**
     * What the frame cost and how it was drawn; read by `noo-kiosk-cdp
     * frame`, and passed through whole by `noo kiosk status --json`.
     *
     * The split matters: `ms` alone says the box is slow but not WHERE,
     * and every guess costs a release cycle to test on the real screen.
     * `dpr` is here because the obvious assumption — that full costs 4x
     * lean because of 2x device pixels — is only true on a display that
     * reports 2, and a shelf monitor usually reports 1.
     */
    __nooKioskFrame?: {
      ms: number;
      quality: Quality;
      sim: number;
      paint: number;
      dpr: number;
      nodes: number;
      links: number;
    };
  }
}
import { structureKey } from './graph/structure';
import { createParticles } from './graph/particles';
import { paint, type Focus } from './graph/render';

/** The graph view. A pure renderer: the store and the stream live in KioskShell. */
export function GraphKiosk({
  state,
  now,
  pager,
  quality,
}: {
  state: KioskState;
  now: number;
  pager?: Pager;
  /** Pinned by `?quality=`; otherwise the governor decides. */
  quality?: Quality;
}) {
  const v = graphView(state, now);
  const src = state.sources.graph;
  const packOff = v.trellion !== 'enabled' && !!state.sources.addons.at;

  return (
    <div className="gkiosk">
      <LivenessBand state={state} now={now} title="NOOMESH · KNOWLEDGE" pager={pager} />
      <section className={`region canvas${src.error ? ' stale' : ''}`}>
        {packOff ? (
          <PackOff word={v.trellion} />
        ) : !v.loaded ? (
          <div className="empty">{src.error ? `knowledge graph unavailable${src.at ? ` · ${fmtDuration(now - src.at)} stale` : ''}` : '…'}</div>
        ) : v.nodes.length === 0 ? (
          <div className="empty">{emptyReason(v)}</div>
        ) : (
          <Cloud view={v} labels={v.labels} quality={quality} />
        )}
        {src.error && src.at && v.loaded && <div className="stale-tag">{fmtDuration(now - src.at)} stale</div>}
      </section>
      <Strip v={v} />
    </div>
  );
}

/** How long a push-in holds, and the least time between two of them. */
const FOCUS_HOLD_S = 14;
const FOCUS_GAP_S = 35;
const FOCUS_ZOOM = 2.4;

/** The canvas and its animation loop. The React tree above re-renders once a second; this runs every frame. */
function Cloud({ view, labels, quality }: { view: GraphView; labels: boolean; quality?: Quality }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const viewRef = useRef(view);
  viewRef.current = view;

  // The simulation is rebuilt only when the structure changes — which
  // entities, which links, as *sets* (graph/structure.ts). An ingest changes
  // degrees and activity, which flow in through refs without a rebuild. When
  // a rebuild is real (an entity appeared), the ones that already existed
  // keep their positions, so a new one grows into the cloud instead of the
  // cloud re-seeding around it.
  const key = useMemo(() => structureKey(view.nodes.map((n) => n.id), view.links), [view.nodes, view.links]);
  const prevSim = useRef<Sim | null>(null);
  const sim = useMemo<Sim>(() => {
    void key;
    const seed2d = layoutGraph({
      nodes: view.nodes.map((n) => ({ id: n.id, name: n.name, type: n.type ?? 'entity', degree: Math.max(1, n.degree) })),
      edges: view.links.map((l) => ({ src: l.src, dst: l.dst, relType: 'RELATED_TO' })),
    });
    const carried = prevSim.current?.positions() ?? {};
    const reduced = typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches;
    const next = createSim(
      {
        nodes: seed2d.nodes.map((n) => {
          const e = view.nodes.find((x) => x.id === n.id)!;
          return {
            id: n.id,
            // Degree, where this was member count. Both are "how big is
            // this thing", and degree is the one the entity view has.
            mass: Math.sqrt(Math.max(1, e.degree)),
            x0: (n.x / seed2d.width) * 2 - 1,
            y0: (n.y / seed2d.height) * 2 - 1,
            at: carried[n.id],
          };
        }),
        // Entity edges carry no weight — one edge is one edge. The cluster
        // view's weight was a count of the entity edges underneath, which
        // is exactly what is being drawn directly now.
        links: view.links.map((l) => ({ a: l.src, b: l.dst, weight: 1 })),
        seed: 7,
      },
      reduced ? { orbit: 0, jitter: 0 } : {},
    );
    prevSim.current = next;
    return next;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const particles = createParticles(3);
    const seenGrew = new Map<string, number>();
    // Slow machine? The governor watches how long each frame's WORK takes
    // and drops to lean on a sustained run; `fit()` re-reads it for dpr.
    const gov = createGovernor({ forced: quality });
    let avgSim = 0;
    let avgPaint = 0;
    let raf = 0;
    let last = performance.now();
    const t0 = last;
    let trickleAcc = 0;
    let W = 0;
    let H = 0;
    let dpr = 1;

    // The camera: eased toward a target. A push-in follows an ingest (the
    // hub it grew), holds, then eases back to the wide view; never more often
    // than FOCUS_GAP_S. With reduced motion — or below the full drawing tier,
    // where it is far too expensive — the camera stays wide. See `mayPushIn`.
    const reduced = typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches;
    const focus: Focus = { x: 0, y: 0, zoom: 1, dof: 0.35 };
    let focusId: string | null = null;
    let focusUntil = 0;
    let lastFocusEnd = -FOCUS_GAP_S;

    const fit = () => {
      const box = canvas.parentElement?.getBoundingClientRect();
      W = Math.max(1, Math.floor(box?.width ?? canvas.clientWidth));
      H = Math.max(1, Math.floor(box?.height ?? canvas.clientHeight));
      // Lean draws at 1× — at 2× the blur and every gradient cost four
      // times the pixels, and a machine in lean has none to spare.
      dpr = gov.quality === 'lean' ? 1 : Math.min(2, window.devicePixelRatio || 1);
      canvas.width = W * dpr;
      canvas.height = H * dpr;
      canvas.style.width = `${W}px`;
      canvas.style.height = `${H}px`;
    };
    fit();
    const ro = new ResizeObserver(fit);
    if (canvas.parentElement) ro.observe(canvas.parentElement);

    const frame = (nowMs: number) => {
      const work0 = performance.now();
      // No catching up below full. The first lean skipped frames and then
      // integrated the skipped time, so every painted frame jumped the
      // cloud 60–90ms forward, which reads as snapping from state to state
      // rather than flowing. Flow is small steps on every paint. So a slow
      // machine gets a slower cloud — each frame advances at most one
      // thirtieth of a second of motion, however late it is — rather than
      // a jerky one. Nothing here is a clock; drift speed is not a fact.
      const dt = Math.min(gov.quality === 'full' ? 0.1 : 1 / 30, (nowMs - last) / 1000);
      last = nowMs;
      const t = (nowMs - t0) / 1000;
      const vw = viewRef.current;
      const wall = Date.now();

      // Activity: recency of the last ingest per entity, decaying over the
      // growth window. This is the number that pulls an entity forward.
      const activity: Record<string, number> = {};
      const tags: Record<string, string[]> = {};
      let maxMass = 1;
      for (const c of vw.nodes) {
        sim.setMass(c.id, Math.sqrt(Math.max(1, c.degree)));
        maxMass = Math.max(maxMass, Math.sqrt(Math.max(1, c.degree)));
        if (c.grewAt != null) {
          const age = wall - c.grewAt;
          if (age >= 0 && age < RECENT_GROWTH_MS) {
            activity[c.id] = Math.pow(1 - age / RECENT_GROWTH_MS, 1.6);
            tags[c.id] = [`GREW=${fmtDuration(age)} ago`];
          }
          // A new growth timestamp = an ingest just landed: stream particles
          // in, and — if the camera is free — push in on it.
          if ((seenGrew.get(c.id) ?? -1) < c.grewAt) {
            seenGrew.set(c.id, c.grewAt);
            const f = sim.project(t);
            const idx = f.nodes.findIndex((n) => n.id === c.id);
            if (idx >= 0 && gov.quality !== 'flat') particles.burst(idx, f.links, gov.quality === 'lean' ? 2 : 4);
            if (
              mayPushIn({
                quality: gov.quality,
                reducedMotion: reduced,
                cameraFree: focusId == null,
                sinceLastPushS: t - lastFocusEnd,
                gapS: FOCUS_GAP_S,
              })
            ) {
              focusId = c.id;
              focusUntil = t + FOCUS_HOLD_S;
            }
          }
        }
      }
      const simT0 = performance.now();
      sim.step(dt, activity);
      const f = sim.project(t);
      const simMs = performance.now() - simT0;

      // Camera easing. While focused, the target follows the hub as it moves.
      if (focusId != null && t > focusUntil) {
        focusId = null;
        lastFocusEnd = t;
      }
      const target = focusId != null ? f.nodes.find((n) => n.id === focusId) : undefined;
      const k = 1 - Math.exp(-dt * (target ? 1.4 : 0.9));
      focus.x += ((target?.x ?? 0) - focus.x) * k;
      focus.y += ((target?.y ?? 0) - focus.y) * k;
      focus.zoom += ((target ? FOCUS_ZOOM : 1) - focus.zoom) * k;
      focus.dof += ((target ? 0.9 : 0.35) - focus.dof) * k;

      // The ambient trickle: a couple of particles a second, somewhere.
      trickleAcc += dt;
      if (gov.quality !== 'flat' && trickleAcc > (gov.quality === 'lean' ? 1.2 : 0.45)) {
        trickleAcc = 0;
        particles.trickle(f.links.length);
      }
      particles.step(dt);

      const paintT0 = performance.now();
      paint(ctx, f, {
        width: W,
        height: H,
        dpr,
        labels,
        // Only populated under `labels`; without it every value here is the
        // id the gateway sent, because no name was sent at all.
        names: Object.fromEntries(vw.nodes.map((c) => [c.id, c.name])),
        tags,
        t,
        maxMass,
        particles: particles.items,
        readout: { entities: vw.gatewayEntityCount, links: vw.edgeCount, linksDrawn: vw.edgesDrawn, growing: vw.recentlyGrown.size },
        focus,
        tier: gov.quality,
      });
      const paintMs = performance.now() - paintT0;
      const before = gov.quality;
      if (gov.observe(performance.now() - work0, nowMs) !== before) fit();
      // Same smoothing as the governor's, so the parts are comparable with
      // the whole rather than being three numbers on different clocks.
      avgSim = smooth(avgSim, simMs);
      avgPaint = smooth(avgPaint, paintMs);
      // For `noo kiosk status` via CDP: the numbers the tier decision is
      // made on. "Choppy" is a feeling; this is what it measures as.
      window.__nooKioskFrame = {
        ms: Math.round(gov.avgMs),
        quality: gov.quality,
        sim: Math.round(avgSim * 10) / 10,
        paint: Math.round(avgPaint * 10) / 10,
        dpr,
        nodes: f.nodes.length,
        links: f.links.length,
      };
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [sim, labels]);

  return <canvas ref={canvasRef} className="cloud" aria-hidden="true" />;
}

/** The knowledge pack is not on. Say which way, in the operator's terms — the same tri-state discipline as the console. */
/**
 * What to say when there is nothing to draw — which is not the same
 * question as whether there is a graph.
 *
 * This screen used to answer it with one sentence: "the graph is empty —
 * nothing ingested yet". On a default install that sentence was FALSE,
 * because the view was cluster-level and clustering is the Intelligent
 * tier. Moving to the entity level removes that whole class of wrongness:
 * `requires_intelligent_tier` cannot be the answer any more, because this
 * view does not need clustering.
 *
 * The cluster-era reasons stay handled anyway. A display can be newer than
 * the gateway it is pointed at, and a sentence invented for an unrecognised
 * word is exactly what this function exists to stop.
 */
function emptyReason(v: GraphView): string {
  const n = v.gatewayEntityCount;
  const entities = n != null && n > 0 ? `${n.toLocaleString()} entities` : 'the graph has entities';

  switch (v.reason) {
    case 'empty_graph':
      return 'the graph is empty — nothing ingested yet';
    case 'below_min_degree':
      // Entities exist; none is connected to two others yet. A freshly
      // ingested graph looks exactly like this for a builder cycle or two,
      // and "nothing ingested" would send the operator to ingest what they
      // have already ingested.
      return `${entities} · none connected enough to draw yet`;
    case 'requires_intelligent_tier':
      return `${entities} · clustering is the Intelligent tier`;
    case 'no_clusters':
      return `${entities} · no clustering pass has run yet`;
    case 'no_clusters_at_this_level':
      // The graph IS clustered — this request's level/min_members matched
      // nothing. Saying "no pass has run" here would send an operator to
      // start a fifteen-minute job that changes nothing.
      return `${entities} · clustered, but none at this level`;
    case 'counts_unavailable':
      // The gateway could not read the counts, so it does not know which
      // kind of empty this is — and neither do we. Anything else here is a
      // guess presented as a fact, on an unattended display, during what is
      // most likely a database incident.
      return 'knowledge graph · counts unavailable';
  }

  // An unrecognised reason is a NEWER gateway, not an older one — this list
  // has grown twice already. Report the gateway's own word rather than
  // inferring around it: a word the operator can search for beats a sentence
  // we made up.
  if (v.reason) return `knowledge graph · ${v.reason.replace(/_/g, ' ')}`;

  // No reason at all: an older gateway. Infer, and only claim what is knowable.
  if (n != null && n > 0) {
    return v.intel === 'enabled'
      ? `${entities} · no clustering pass has run yet`
      : `${entities} · clustering is the Intelligent tier`;
  }
  if (v.intel !== 'enabled' && v.intel !== 'unknown') {
    // No count either way, but we know clusters could never appear — so do
    // not assert the graph is empty, because we cannot see whether it is.
    return 'no clusters · clustering is the Intelligent tier';
  }
  return 'the graph is empty — nothing ingested yet';
}

function PackOff({ word }: { word: AddonWord }) {
  const meaning: Record<AddonWord, string> = {
    enabled: '',
    disabled: 'the operator turned Trellion off. Not a fault.',
    unlicensed: 'on, but no entitlement grants it.',
    unhealthy: 'on, but not responding.',
    unknown: 'the gateway did not say.',
  };
  return (
    <div className={`packoff ${word}`}>
      <div className="w">knowledge pack {word}</div>
      <div className="m">{meaning[word]}</div>
    </div>
  );
}

function Strip({ v }: { v: GraphView }) {
  const n = (x: number | null) => (x == null ? '—' : x.toLocaleString());
  const growing = v.recentlyGrown.size;
  return (
    <div className="strip">
      <span>
        <b>{n(v.nodes.length ? v.nodes.length : null)}</b> shown
      </span>
      <span>
        <b>{n(v.gatewayEntityCount)}</b> entities
      </span>
      <span>
        <b>{n(v.edgeCount)}</b> links
      </span>
      <span className={growing > 0 ? 'hot' : ''}>
        <b>{growing}</b> growing
      </span>
      <span className={v.addedSinceConnect > 0 ? 'hot' : ''}>
        <b>+{v.addedSinceConnect}</b> since connect
      </span>
      <span>
        last ingest <b>{v.lastIngestMs == null ? 'none seen' : `${fmtDuration(v.lastIngestMs)} ago`}</b>
      </span>
      <span className={`pack ${v.trellion}`}>
        trellion <b>{v.trellion}</b>
      </span>
      {v.labels && (
        // The operator's switch, visible to whoever is standing here: these
        // dots are named people, documents and customers right now.
        <span className="labels-on" title="entity names are shown: kiosk.graph_labels is on at the controller">
          <b>LABELS ON</b>
        </span>
      )}
    </div>
  );
}
