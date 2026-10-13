// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect } from 'vitest';
import {
  initial,
  applySource,
  applySourceError,
  applyEvent,
  noteKeepalive,
  liveness,
  fleet,
  pressure,
  work,
  exceptions,
  fmtDuration,
  fmtSince,
  graphView,
  RELOAD_AFTER_MS,
  DEFAULT_KEEPALIVE_MS,
  STALE_KEEPALIVES,
  REFRESH_DATA_AFTER_MS,
  shouldRefreshData,
  RECENT_GROWTH_MS,
  type SourceData,
} from './store';

const T0 = Date.parse('2026-09-04T12:00:00Z');
const ev = (event: string, data: Record<string, unknown>, id = 'e1') => ({ id, event, data: JSON.stringify(data) });
const iso = (t: number) => new Date(t).toISOString();

describe('snapshot', () => {
  it('a node first seen in a snapshot has an observed (≥) since, not an exact one', () => {
    const s = applySource(initial(), 'cluster', [{ id: 'a', hostname: 'a', status: 'online' }], T0);
    expect(s.nodes.a!.since).toEqual({ at: T0, exact: false });
    expect(fmtSince(s.nodes.a!.since, T0 + 90_000)).toBe('≥ 1m');
  });

  it('a snapshot that shows a changed status resets since and logs a transition marked as noticed', () => {
    let s = applySource(initial(), 'cluster', [{ id: 'a', hostname: 'a', status: 'online' }], T0);
    s = applySource(s, 'cluster', [{ id: 'a', hostname: 'a', status: 'offline' }], T0 + 60_000);
    expect(s.nodes.a!.status).toBe('offline');
    expect(s.nodes.a!.since).toEqual({ at: T0 + 60_000, exact: false });
    expect(s.transitions[0]!.text).toBe('a online → offline (noticed on refresh)');
    expect(s.transitions[0]!.severity).toBe('bad');
  });

  it('a snapshot with the same status keeps the earlier since', () => {
    let s = applySource(initial(), 'cluster', [{ id: 'a', status: 'busy' }], T0);
    s = applySource(s, 'cluster', [{ id: 'a', status: 'busy' }], T0 + 60_000);
    expect(s.nodes.a!.since.at).toBe(T0);
    expect(s.transitions).toHaveLength(0);
  });

  it('drops a node with no identity, and terminal jobs', () => {
    const s = applySource(initial(), 'cluster', [{ id: '', hostname: '', status: 'online' }], T0);
    expect(Object.keys(s.nodes)).toHaveLength(0);
    const j = applySource(initial(), 'jobs', [
      { job_id: 'q', status: 'queued', created_at: iso(T0 - 5000) },
      { job_id: 'c', status: 'completed' },
      { job_id: 'x', status: 'cancelled' },
    ], T0);
    expect(Object.keys(j.jobs)).toEqual(['q']);
  });

  it('marks the source fresh and bumps both clocks — a snapshot IS data', () => {
    const s = applySource(initial(), 'scheduler', { running: true, paused: false, queue_depth: 2 }, T0);
    expect(s.sources.scheduler).toEqual({ at: T0, error: null });
    expect(s.lastData).toBe(T0);
    expect(s.lastContact).toBe(T0);
  });

  it('a source error keeps the last-good timestamp and records the error', () => {
    let s = applySource(initial(), 'scheduler', { running: true }, T0);
    s = applySourceError(s, 'scheduler', 'HTTP 503', T0 + 1000);
    expect(s.sources.scheduler).toEqual({ at: T0, error: 'HTTP 503' });
    expect(s.scheduler?.running).toBe(true); // stale data stays, aged
  });
});

describe('events', () => {
  it('hello sets the keepalive interval, which sets the stale threshold', () => {
    const s = applyEvent(initial(), ev('hello', { keepalive_ms: 5000, ts: iso(T0) }), T0);
    expect(s.keepaliveMs).toBe(5000);
    expect(liveness(s, T0).thresholdMs).toBe(5000 * STALE_KEEPALIVES);
  });

  it('node.state gives an exact since from the event timestamp, not arrival time', () => {
    const arrived = T0 + 4000;
    const s = applyEvent(initial(), ev('node.state', { node_id: 'a', hostname: 'a', status: 'offline', previous: 'busy', ts: iso(T0) }), arrived);
    expect(s.nodes.a!.since).toEqual({ at: T0, exact: true });
    expect(fmtSince(s.nodes.a!.since, T0 + 120_000)).toBe('2m');
    expect(s.transitions[0]).toMatchObject({ at: T0, text: 'a busy → offline', severity: 'bad' });
    expect(s.lastData).toBe(arrived);
  });

  it('a node.state with an unchanged status is a no-op transition', () => {
    let s = applyEvent(initial(), ev('node.state', { node_id: 'a', status: 'online', ts: iso(T0) }), T0);
    s = applyEvent(s, ev('node.state', { node_id: 'a', status: 'online', ts: iso(T0 + 1000) }, 'e2'), T0 + 1000);
    expect(s.transitions).toHaveLength(1);
    expect(s.nodes.a!.since.at).toBe(T0);
  });

  it('gpu.sample tracks pinned duration across samples and clears it when utilisation drops', () => {
    const g = (u: number, t: number, id: string) => ev('gpu.sample', { node_id: 'n', index: '0', name: 'X', utilization: u, ts: iso(t) }, id);
    let s = applyEvent(initial(), g(95, T0, 'a'), T0);
    expect(s.gpus['n/0']!.pinnedSince).toEqual({ at: T0, exact: true });
    s = applyEvent(s, g(93, T0 + 30_000, 'b'), T0 + 30_000);
    expect(s.gpus['n/0']!.pinnedSince?.at).toBe(T0); // still the first pinned sample
    s = applyEvent(s, g(40, T0 + 60_000, 'c'), T0 + 60_000);
    expect(s.gpus['n/0']!.pinnedSince).toBeNull();
  });

  it('a snapshot GPU already pinned starts an observed pinned duration', () => {
    const s = applySource(initial(), 'gpus', [{ node_id: 'n', index: 0, name: 'X', utilization: 97 }], T0);
    expect(s.gpus['n/0']!.pinnedSince).toEqual({ at: T0, exact: false });
  });

  it('job.state: failed logs a transition with the error; completed removes the job', () => {
    let s = applyEvent(initial(), ev('job.state', { job_id: 'j-abcdefghijklmnop', status: 'failed', node_id: 'n', error: 'OOM', ts: iso(T0) }), T0);
    expect(s.transitions[0]!.text).toBe('job j-abcdefghij failed on n — OOM');
    expect(s.jobs['j-abcdefghijklmnop']!.status).toBe('failed');
    s = applyEvent(s, ev('job.state', { job_id: 'j-abcdefghijklmnop', status: 'completed', ts: iso(T0) }, 'e2'), T0);
    expect(s.jobs['j-abcdefghijklmnop']).toBeUndefined();
  });

  it('heartbeat.task: failure is an exception until the same task reports ok, which logs a recovery', () => {
    let s = applyEvent(initial(), ev('heartbeat.task', { task: 'rag_reindex', ok: false, error: 'timeout', ts: iso(T0) }), T0);
    expect(exceptions(s, T0)).toEqual([{ key: 'task:rag_reindex', text: 'rag_reindex failing — timeout', since: T0, severity: 'bad' }]);
    s = applyEvent(s, ev('heartbeat.task', { task: 'rag_reindex', ok: true, ts: iso(T0 + 5000) }, 'e2'), T0 + 5000);
    expect(exceptions(s, T0 + 5000)).toEqual([]);
    expect(s.transitions[0]!.text).toBe('task rag_reindex recovered');
  });

  it('scheduler.state logs pause/resume only when the state actually changes', () => {
    let s = applySource(initial(), 'scheduler', { running: true, paused: false }, T0);
    s = applyEvent(s, ev('scheduler.state', { running: true, paused: false, queue_depth: 4, ts: iso(T0) }), T0);
    expect(s.transitions).toHaveLength(0);
    expect(s.scheduler?.queueDepth).toBe(4);
    s = applyEvent(s, ev('scheduler.state', { running: true, paused: true, ts: iso(T0) }, 'e2'), T0);
    expect(s.transitions[0]!.text).toBe('scheduler paused');
  });

  // These arrived, so the pipe is open — but nothing on the wall changed,
  // so they are contact and not data. The band's number is the age of the
  // PICTURE, and an event this page cannot render did not refresh it.
  it('unknown events and malformed data are contact, never data', () => {
    let s = applyEvent(initial(), ev('something.else', { ts: iso(T0) }), T0);
    expect(s.lastContact).toBe(T0);
    expect(s.lastData).toBeNull();
    s = applyEvent(s, { id: null, event: 'node.state', data: 'not json' }, T0 + 1);
    expect(s.lastContact).toBe(T0 + 1);
    expect(s.lastData).toBeNull();
    expect(Object.keys(s.nodes)).toHaveLength(0);
  });

  it('hello is a handshake, not data: it moves contact and leaves the picture aged', () => {
    let s = applyEvent(initial(), ev('node.state', { node_id: 'a', status: 'online', ts: iso(T0) }), T0);
    expect(s.lastData).toBe(T0);
    // A reconnect an hour later re-announces hello. The picture is an hour
    // old and must keep saying so.
    const later = T0 + 3_600_000;
    s = applyEvent(s, ev('hello', { keepalive_ms: 15000, ts: iso(later) }, 'e2'), later);
    expect(s.lastContact).toBe(later);
    expect(s.lastData).toBe(T0);
    expect(liveness(s, later).dataAgeMs).toBe(3_600_000);
  });

  it('caps the transition log', () => {
    let s = initial();
    for (let i = 0; i < 20; i++) {
      s = applyEvent(s, ev('node.state', { node_id: `n${i}`, status: 'offline', ts: iso(T0 + i) }, `e${i}`), T0 + i);
    }
    expect(s.transitions).toHaveLength(12);
    expect(s.transitions[0]!.text).toBe('n19 ? → offline');
  });
});

describe('liveness', () => {
  it('is neither stale nor dead before anything arrives', () => {
    expect(liveness(initial(), T0)).toEqual({
      contactAgeMs: null,
      dataAgeMs: null,
      thresholdMs: DEFAULT_KEEPALIVE_MS * STALE_KEEPALIVES,
      stale: false,
      dead: false,
      // Nothing is connected, so there is no picture to be stale.
      dataStale: false,
    });
  });

  it('a keepalive keeps the CONNECTION healthy: stale past N keepalives, dead past the reload threshold', () => {
    const s = noteKeepalive(initial(), T0);
    const thr = DEFAULT_KEEPALIVE_MS * STALE_KEEPALIVES;
    expect(liveness(s, T0 + thr).stale).toBe(false);
    expect(liveness(s, T0 + thr + 1).stale).toBe(true);
    expect(liveness(s, T0 + RELOAD_AFTER_MS).dead).toBe(false);
    expect(liveness(s, T0 + RELOAD_AFTER_MS + 1).dead).toBe(true);
  });

  // THE BUG, as it appeared on the wall. The band read "live · 3s since
  // last data" beside a graph that was hours old, because every keepalive
  // reset the one clock both questions were asked of.
  it('a keepalive does NOT make the picture fresh', () => {
    let s = applySource(initial(), 'scheduler', { running: true }, T0);
    const hours = T0 + 4 * 3_600_000;
    // Four hours of a perfectly healthy stream carrying nothing.
    for (let t = T0 + DEFAULT_KEEPALIVE_MS; t <= hours; t += DEFAULT_KEEPALIVE_MS) {
      s = noteKeepalive(s, t);
    }
    const l = liveness(s, hours);
    expect(l.stale).toBe(false); // the connection really is fine
    expect(l.dead).toBe(false); // and must not trigger the reload
    expect(l.contactAgeMs).toBe(0);
    expect(l.dataAgeMs).toBe(4 * 3_600_000); // the picture is four hours old
    expect(l.dataStale).toBe(true); // and the display has to say so
  });

  it('data younger than the refresh window is not stale; older is', () => {
    const s = applySource(initial(), 'scheduler', { running: true }, T0);
    expect(liveness(s, T0 + REFRESH_DATA_AFTER_MS).dataStale).toBe(false);
    expect(liveness(s, T0 + REFRESH_DATA_AFTER_MS + 1).dataStale).toBe(true);
  });

  it('connected with nothing ever received is stale, not fresh', () => {
    const s = noteKeepalive(initial(), T0);
    expect(liveness(s, T0).dataAgeMs).toBeNull();
    expect(liveness(s, T0).dataStale).toBe(true);
  });
});

describe('shouldRefreshData', () => {
  const W = REFRESH_DATA_AFTER_MS;
  /** A healthy stream that has been keeping alive but carrying nothing since T0. */
  const quiet = (until: number) => {
    let s = applySource(initial(), 'scheduler', { running: true }, T0);
    for (let t = T0 + DEFAULT_KEEPALIVE_MS; t <= until; t += DEFAULT_KEEPALIVE_MS) s = noteKeepalive(s, t);
    return s;
  };

  it('does nothing while data is arriving', () => {
    const s = applySource(initial(), 'scheduler', { running: true }, T0);
    expect(shouldRefreshData(s, T0 + W, 0)).toBe(false);
  });

  it('re-fetches once the picture is older than the window', () => {
    expect(shouldRefreshData(quiet(T0 + W + 1000), T0 + W + 1000, 0)).toBe(true);
  });

  // Without this it fires every tick for the rest of the display's life —
  // a once-a-second poll against the gateway, installed by a fix for the
  // opposite problem.
  it('does not fire again inside the same window', () => {
    const at = T0 + W + 1000;
    expect(shouldRefreshData(quiet(at), at, at - 1)).toBe(false);
    const later = at + W + 1;
    expect(shouldRefreshData(quiet(later), later, at)).toBe(true);
  });

  // A dead stream already re-fetches when it reconnects. Adding a second
  // fetcher here would hit a gateway that is down once a second.
  it('does not fire while the connection itself is stale', () => {
    let s = applySource(initial(), 'scheduler', { running: true }, T0);
    s = noteKeepalive(s, T0);
    const long = T0 + W + 1000; // nothing at all has arrived since T0
    expect(liveness(s, long).stale).toBe(true);
    expect(shouldRefreshData(s, long, 0)).toBe(false);
  });

  it('does not fire before the page has ever connected', () => {
    expect(shouldRefreshData(initial(), T0 + W * 10, 0)).toBe(false);
  });
});

describe('selectors', () => {
  it('fleet puts a node down first, then unknown, busy, online', () => {
    const s = applySource(initial(), 'cluster', [
      { id: 'z', status: 'online' },
      { id: 'b', status: 'busy' },
      { id: 'a', status: 'online' },
      { id: 'd', status: 'offline' },
      { id: 'u', status: 'weird' },
    ], T0);
    expect(fleet(s).map((n) => n.id)).toEqual(['d', 'u', 'b', 'a', 'z']);
  });

  it('pressure is hottest first; a GPU with no reading sorts last', () => {
    const s = applySource(initial(), 'gpus', [
      { node_id: 'a', index: 0, utilization: 40 },
      { node_id: 'b', index: 0, utilization: null },
      { node_id: 'c', index: 0, utilization: 91 },
    ], T0);
    expect(pressure(s).map((g) => g.key)).toEqual(['c/0', 'a/0', 'b/0']);
  });

  it('work reports the age of the oldest waiting job and falls back to counting jobs when the scheduler is unknown', () => {
    const s = applySource(initial(), 'jobs', [
      { job_id: 'q1', status: 'queued', created_at: iso(T0 - 40 * 60_000) },
      { job_id: 'q2', status: 'queued', created_at: iso(T0 - 60_000) },
      { job_id: 'r1', status: 'running' },
    ], T0);
    const w = work(s, T0);
    expect(w).toEqual({ queueDepth: 2, active: 1, oldestWaitingMs: 40 * 60_000, schedulerWord: 'unknown' });
    const s2 = applySource(s, 'scheduler', { running: true, paused: false, queue_depth: 7, active_jobs: 3 }, T0);
    expect(work(s2, T0)).toMatchObject({ queueDepth: 7, active: 3, schedulerWord: 'running' });
  });

  it('work reports nothing before the jobs source has loaded', () => {
    expect(work(initial(), T0)).toEqual({ queueDepth: null, active: null, oldestWaitingMs: null, schedulerWord: 'unknown' });
  });

  it('exceptions: a failed source renders as an age, and memory grade D/F is a warning', () => {
    let s = applySource(initial(), 'cluster', [], T0);
    s = applySourceError(s, 'cluster', 'HTTP 500', T0 + 1000);
    s = applySourceError(s, 'rag', 'network', T0 + 1000);
    s = applySource(s, 'memory', { grade: 'F', warnings: ['Only 12.0% of entries embedded'] }, T0);
    const ex = exceptions(s, T0 + 4 * 60_000);
    expect(ex.map((e) => e.text)).toEqual([
      'memory grade F — Only 12.0% of entries embedded',
      'cluster · 4m stale',
      'rag · never loaded',
    ]);
  });

  it('exceptions is empty when everything is normal — the wallpaper rule', () => {
    let s = applySource(initial(), 'scheduler', { running: true, paused: false }, T0);
    s = applySource(s, 'heartbeat', { enabled: true, running: true }, T0);
    s = applySource(s, 'memory', { grade: 'A', warnings: [] }, T0);
    s = applySource(s, 'rag', { started: true, doc_count: 3 }, T0);
    expect(exceptions(s, T0)).toEqual([]);
  });
});

describe('graph view', () => {
  // What /api/kiosk/graph sends while the controller's kiosk.graph_labels is
  // OFF — which is the default and the one that matters. No `name`, no
  // `rel_type`: the gateway never put them on the wire. `id` is a UUID, not
  // the entity text.
  const overview = {
    nodes: [
      { id: 'a', type: 'person', degree: 9 },
      { id: 'b', type: 'concept', degree: 5 },
      { id: 'c', type: 'document', degree: 2 },
    ],
    edges: [
      { src: 'a', dst: 'b' },
      { src: 'b', dst: 'zzz' }, // dangling — dropped
    ],
    stats: { node_count: 3, edge_count: 2 },
    entity_count: 4538,
  };

  it('reports how many edges are drawn AND how many exist, when the gateway caps them', () => {
    // The live display: 160 nodes, 4,570 edges between them. The gateway
    // now sends a readable subset and says so. Reporting only the total
    // beside a thinned picture is the quiet version of the lie the
    // liveness band used to tell.
    const capped = {
      ...overview,
      edges_drawn: 1,
      edges_total: 4570,
      stats: { node_count: 3, edge_count: 4570 },
    };
    const v = graphView(applySource(initial(), 'graph', capped, T0), T0);
    expect(v.edgeCount).toBe(4570);
    expect(v.edgesDrawn).toBe(1);
  });

  it('falls back to what arrived on a gateway from before the cap', () => {
    const v = graphView(applySource(initial(), 'graph', overview, T0), T0);
    // One link survives the dangling-link filter, and nothing claims more.
    expect(v.edgesDrawn).toBe(1);
    expect(v.edgeCount).toBe(2);
  });

  it('most-connected first, dangling links dropped, entity count from the gateway', () => {
    const s = applySource(initial(), 'graph', overview, T0);
    const v = graphView(s, T0);
    expect(v.nodes.map((n) => n.id)).toEqual(['a', 'b', 'c']);
    // The WHOLE graph, not the three hubs on screen. Deriving it from
    // nodes.length would make the two always agree and never be right.
    expect(v.gatewayEntityCount).toBe(4538);
    expect(v.edgeCount).toBe(2);
    expect(v.links).toEqual([{ src: 'a', dst: 'b' }]);
    expect(v.loaded).toBe(true);
    expect(v.lastIngestMs).toBeNull();
    expect(v.addedSinceConnect).toBe(0);
  });

  // THE PRIVACY DEFAULT, asserted on the page's side of the wire. The
  // gateway's guard proves it does not send a name; this proves the page
  // does not invent one. `name` falls back to the id, which is a UUID.
  it('without labels there is no name: the id is what a renderer gets', () => {
    const s = applySource(initial(), 'graph', overview, T0);
    const v = graphView(s, T0);
    for (const n of v.nodes) {
      expect(n.name).toBe(n.id);
    }
    expect(JSON.stringify(v)).not.toContain('person named');
  });

  it('with labels the name is carried through, and the view says labels are on', () => {
    const labelled = { ...overview, labels: true, nodes: overview.nodes.map((n) => ({ ...n, name: `name-of-${n.id}` })) };
    const v = graphView(applySource(initial(), 'graph', labelled, T0), T0);
    expect(v.nodes.find((n) => n.id === 'a')?.name).toBe('name-of-a');
    expect(v.labels).toBe(true);
  });

  it('labels are off by default, and an older gateway that sends no flag reads as off', () => {
    expect(graphView(applySource(initial(), 'graph', overview, T0), T0).labels).toBe(false);
    expect(graphView(applySource(initial(), 'graph', { ...overview, labels: false }, T0), T0).labels).toBe(false);
    expect(graphView(initial(), T0).labels).toBe(false);
  });

  // The marker and the names come from one value. A name that arrives
  // WITHOUT the gateway saying labels are on is not drawn, so the screen
  // can never show names while the LABELS ON marker is absent.
  it('a name without labels:true is not shown', () => {
    const stray = { ...overview, labels: false, nodes: overview.nodes.map((n) => ({ ...n, name: `name-of-${n.id}` })) };
    const v = graphView(applySource(initial(), 'graph', stray, T0), T0);
    for (const n of v.nodes) expect(n.name).toBe(n.id);
    expect(JSON.stringify(v)).not.toContain('name-of-');
  });

  it('switching labels off at the controller takes names off the wall on the next fetch', () => {
    const named = { ...overview, labels: true, nodes: overview.nodes.map((n) => ({ ...n, name: `name-of-${n.id}` })) };
    let s = applySource(initial(), 'graph', named, T0);
    expect(graphView(s, T0).labels).toBe(true);
    s = applySource(s, 'graph', overview, T0 + 10_000);
    const v = graphView(s, T0 + 10_000);
    expect(v.labels).toBe(false);
    expect(JSON.stringify(v)).not.toContain('name-of-');
  });

  it('graph.delta counts the ingest and the edges; it no longer touches nodes', () => {
    let s = applySource(initial(), 'graph', overview, T0);
    // The `clusters` array is still sent by the mock and by an older
    // gateway. Those are CLUSTER ids and the wall holds ENTITY ids, so the
    // old loop invented a node with degree 0 for every one it did not know.
    s = applyEvent(
      s,
      ev('graph.delta', { entities_added: 7, edges_added: 2, clusters: [{ id: 'c03', member_count: 15 }], ts: iso(T0 + 1000) }),
      T0 + 1000,
    );
    const v = graphView(s, T0 + 61_000);
    expect(v.nodes.map((n) => n.id)).toEqual(['a', 'b', 'c']); // no phantom c03
    expect(v.edgeCount).toBe(4);
    expect(v.addedSinceConnect).toBe(7);
    expect(v.lastIngestMs).toBe(60_000);
    expect(s.transitions[0]!.text).toBe('ingest +7 entities');
  });

  it('a refreshed snapshot with a higher degree is an ingest seen late: grewAt, counters, a transition', () => {
    let s = applySource(initial(), 'graph', overview, T0);
    const grown = {
      ...overview,
      nodes: overview.nodes.map((n) => (n.id === 'a' ? { ...n, degree: 12 } : n.id === 'c' ? { ...n, degree: 3 } : n)),
    };
    s = applySource(s, 'graph', grown, T0 + 30_000);
    expect(s.graph?.nodes.a?.grewAt).toBe(T0 + 30_000);
    expect(s.graph?.nodes.c?.grewAt).toBe(T0 + 30_000);
    expect(s.graph?.nodes.b?.grewAt).toBeNull();
    expect(s.ingest).toEqual({ lastAt: T0 + 30_000, addedSinceConnect: 4 });
    expect(s.transitions[0]!.text).toBe('ingest +4 links · 2 entities grew (noticed on refresh)');
    expect(graphView(s, T0 + 31_000).recentlyGrown).toEqual(new Set(['a', 'c']));
    // past the window, the pulse stops
    expect(graphView(s, T0 + 30_000 + RECENT_GROWTH_MS + 1).recentlyGrown.size).toBe(0);
  });

  // An entity appearing for the first time must NOT read as growth, or the
  // very first snapshot is one enormous fictional ingest.
  it('the first snapshot is not an ingest', () => {
    const s = applySource(initial(), 'graph', overview, T0);
    expect(s.ingest.addedSinceConnect).toBe(0);
    expect(s.transitions).toHaveLength(0);
    expect(Object.values(s.graph!.nodes).every((n) => n.grewAt == null)).toBe(true);
  });

  it('a refreshed snapshot with the same or lower degree is not an ingest', () => {
    let s = applySource(initial(), 'graph', overview, T0);
    const shrunk = { ...overview, nodes: overview.nodes.map((n) => (n.id === 'a' ? { ...n, degree: 4 } : n)) };
    s = applySource(s, 'graph', shrunk, T0 + 30_000);
    expect(s.ingest.addedSinceConnect).toBe(0);
    expect(s.transitions).toHaveLength(0);
    expect(s.graph?.nodes.a?.degree).toBe(4);
  });

  it('a snapshot refresh keeps grewAt so a reconnect does not drop the pulse', () => {
    let s = applySource(initial(), 'graph', overview, T0);
    const grown = { ...overview, nodes: overview.nodes.map((n) => (n.id === 'a' ? { ...n, degree: 12 } : n)) };
    s = applySource(s, 'graph', grown, T0 + 1000);
    s = applySource(s, 'graph', grown, T0 + 5000);
    expect(s.graph?.nodes.a?.grewAt).toBe(T0 + 1000);
  });

  it('graph.delta before any snapshot still counts the ingest', () => {
    const s = applyEvent(initial(), ev('graph.delta', { entities_added: 3, ts: iso(T0) }), T0);
    expect(s.graph).toBeNull();
    expect(s.ingest).toEqual({ lastAt: T0, addedSinceConnect: 3 });
  });

  it('the pack state comes from the addons source and is unknown until it has answered', () => {
    expect(graphView(initial(), T0).trellion).toBe('unknown');
    let s = applySource(initial(), 'addons', { trellion: 'enabled', evolve: 'disabled', trellion_intel: 'unlicensed' }, T0);
    expect(graphView(s, T0).trellion).toBe('enabled');
    expect(s.addons).toEqual({ trellion: 'enabled', evolve: 'disabled', trellion_intel: 'unlicensed' });
    s = applySource(s, 'addons', { trellion: 'something-new' }, T0);
    expect(graphView(s, T0).trellion).toBe('unknown');
    s = applySource(s, 'addons', {}, T0);
    expect(graphView(s, T0).trellion).toBe('unknown');
  });
});

describe('formatting', () => {
  it('fmtDuration', () => {
    expect(fmtDuration(0)).toBe('0s');
    expect(fmtDuration(59_000)).toBe('59s');
    expect(fmtDuration(60_000)).toBe('1m');
    expect(fmtDuration(3_720_000)).toBe('1h 2m');
    expect(fmtDuration(26 * 3_600_000)).toBe('1d 2h');
    expect(fmtDuration(-5)).toBe('0s');
  });
});

describe('an empty node list is several different situations', () => {
  // The screen used to answer all of them with "the graph is empty —
  // nothing ingested yet". On a default install that was false: the view
  // was cluster-level and clustering is the Intelligent tier, so a mesh
  // with a thousand documents in it displayed, in a hallway, that nothing
  // had been ingested. Moving to the entity level removes that cause;
  // keeping these guards is what stops a new one growing back.

  const overview = (extra: Record<string, unknown>) =>
    ({ nodes: [], edges: [], stats: { node_count: 0, edge_count: 0 }, ...extra }) as SourceData['graph'];

  it('carries the gateway reason and entity count through to the view', () => {
    let s = initial();
    s = applySource(s, 'graph', overview({ reason: 'below_min_degree', entity_count: 1240 }), 1000);
    const v = graphView(s, 1000);
    expect(v.reason).toBe('below_min_degree');
    expect(v.gatewayEntityCount).toBe(1240);
    expect(v.nodes).toHaveLength(0);
  });

  it('an empty node list does not mean an empty graph', () => {
    // Nothing is drawable and the graph holds 900 entities. Reading
    // "nothing on screen" as "nothing known" is exactly the mistake, and
    // it is the one that put "nothing ingested yet" on a hallway wall.
    let s = initial();
    s = applySource(s, 'graph', overview({ reason: 'below_min_degree', entity_count: 900 }), 1000);
    const v = graphView(s, 1000);
    expect(v.nodes).toHaveLength(0);
    expect(v.gatewayEntityCount).toBe(900);
  });

  it('leaves both null on a gateway too old to send them', () => {
    let s = initial();
    s = applySource(s, 'graph', overview({}), 1000);
    const v = graphView(s, 1000);
    expect(v.reason).toBeNull();
    expect(v.gatewayEntityCount).toBeNull();
  });

  it('reports the Intelligent tier separately from the knowledge pack', () => {
    // It no longer decides whether this screen has content — the entity
    // view needs no clustering. It still says what the graph LOOKS like:
    // the open tier writes two edge types and every edge means the same
    // thing, so a flat graph is normal rather than broken.
    let s = initial();
    s = applySource(s, 'addons', { trellion: 'enabled', trellion_intel: 'disabled' }, 1000);
    const v = graphView(s, 1000);
    expect(v.trellion).toBe('enabled');
    expect(v.intel).toBe('disabled');
  });

  it('is unknown until /health has answered, for both', () => {
    const v = graphView(initial(), 1000);
    expect(v.trellion).toBe('unknown');
    expect(v.intel).toBe('unknown');
  });
});

describe('the empty-reason vocabulary is the gateway\u00b4s, and it grows', () => {
  // It grew twice in one afternoon: `no_clusters_at_this_level` and
  // `counts_unavailable` were added to the gateway hours after this display
  // learned the first three. Both fell through the switch into an inference
  // branch that asserted the opposite of the truth — "no pass has run" for a
  // graph that IS clustered, and "nothing ingested yet" during a database
  // incident, which is the exact sentence this file exists to have removed.
  const overview = (extra: Record<string, unknown>) =>
    ({ nodes: [], edges: [], stats: { node_count: 0, edge_count: 0 }, ...extra }) as SourceData['graph'];

  it('carries an unrecognised reason through instead of inferring around it', () => {
    let s = initial();
    s = applySource(s, 'graph', overview({ reason: 'some_future_reason', entity_count: 5 }), 1000);
    expect(graphView(s, 1000).reason).toBe('some_future_reason');
  });

  it('keeps entity_count null when the gateway could not count', () => {
    // `counts_unavailable` comes with nulls, deliberately: a failed count is
    // not a count of zero, and the display must not turn it into one.
    let s = initial();
    s = applySource(s, 'graph', overview({ reason: 'counts_unavailable', entity_count: null }), 1000);
    const v = graphView(s, 1000);
    expect(v.reason).toBe('counts_unavailable');
    expect(v.gatewayEntityCount).toBeNull();
  });

  // A display can be NEWER than the gateway it is pointed at, so the
  // cluster-era words still have to arrive intact rather than be guessed
  // around. They are no longer produced by this route.
  it('still carries a cluster-era reason from an older gateway', () => {
    let s = initial();
    s = applySource(s, 'graph', overview({ reason: 'no_clusters_at_this_level', entity_count: 40 }), 1000);
    expect(graphView(s, 1000).reason).toBe('no_clusters_at_this_level');
  });
});
