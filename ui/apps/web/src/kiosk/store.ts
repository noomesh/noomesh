// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Kiosk state: a pure reducer over the connect-time snapshot and the event
// stream, and the selectors that turn it into what the screen shows.
//
// Two rules from the proposal shape everything here:
//   - Duration is the payload. Nearly every cell pairs a state with how long
//     it has held, so every state carries a `since`.
//   - Degrade visibly. A cell whose source failed says so with an age, never
//     a confident stale number — so every source carries its own freshness.
//
// `since` has two provenances and the screen shows the difference: an event
// gives the exact moment (`exact: true`); a snapshot only proves the state
// held from the moment we looked, so the duration is a lower bound and
// renders with a "≥". Without that distinction a display that reloaded five
// minutes ago would claim every node had been up for five minutes.
//
// No React, no fetch, no DOM: everything here is testable with plain values.

import type { StreamEvent } from '@metis/api';
import { num } from '@/lib/num';

export type NodeStatus = 'online' | 'busy' | 'offline' | 'unknown';
export type SourceKey = 'cluster' | 'gpus' | 'jobs' | 'scheduler' | 'heartbeat' | 'memory' | 'rag' | 'graph' | 'addons';
export const SOURCES: readonly SourceKey[] = ['cluster', 'gpus', 'jobs', 'scheduler', 'heartbeat', 'memory', 'rag', 'graph', 'addons'];
/** The health view's sources. */
export const HEALTH_SOURCES: readonly SourceKey[] = ['cluster', 'gpus', 'jobs', 'scheduler', 'heartbeat', 'memory', 'rag'];
/** The graph view's sources: the cluster overview, and /health for whether the knowledge pack is even on. */
export const GRAPH_SOURCES: readonly SourceKey[] = ['graph', 'addons'];

/**
 * Add-on state word from `/health`. The gateway emits enabled | disabled |
 * unlicensed today; `unhealthy` is specced and not yet emitted. Anything else
 * is `unknown` — neither green nor red, because guessing is worse.
 */
export type AddonWord = 'enabled' | 'disabled' | 'unlicensed' | 'unhealthy' | 'unknown';

// ── Inputs: what the snapshot GETs yield, already narrowed by the hook ──────

export interface SnapshotNode {
  id: string;
  hostname?: string | null;
  status?: string | null;
  running_backends?: Record<string, string> | null;
  tier?: number | null;
}
export interface SnapshotGpu {
  node_id?: string | null;
  hostname?: string | null;
  index?: string | number | null;
  name?: string | null;
  utilization?: number | null;
  memory_used?: number | null;
  memory_total?: number | null;
  temperature?: number | null;
}
export interface SnapshotJob {
  job_id: string;
  status?: string | null;
  type?: string | null;
  node_id?: string | null;
  created_at?: string | null;
}
export interface SnapshotScheduler {
  running?: boolean;
  paused?: boolean;
  queue_depth?: number;
  active_jobs?: number;
  error?: string;
}
export interface SnapshotHeartbeat {
  enabled?: boolean;
  running?: boolean;
}
export interface SnapshotMemory {
  grade?: string | null;
  warnings?: string[];
  error?: string | null;
}
export interface SnapshotRag {
  started?: boolean;
  unembedded_chunks?: number;
  doc_count?: number;
}

/**
 * `/api/kiosk/graph` — the knowledge graph at ENTITY level, projected.
 *
 * Not the general route. The gateway decides at FETCH time whether a name
 * goes on the wire — from the controller's `kiosk.graph_labels` setting,
 * which the operator switches with `noo kiosk labels on|off` and which
 * nothing on this page can ask for. Off (the default), there is no `name`
 * field here to leak — the browser never holds one. An entity name is a
 * person, a document, a customer: MORE sensitive than the cluster labels
 * this view used to show, not less.
 *
 * `id` is a UUID, not the entity text. If that ever stopped being true the
 * switch would be decorative, so the gateway guards it.
 */
export interface SnapshotGraph {
  /**
   * Whether this answer carries names — the controller's switch, as the
   * gateway applied it to THIS response. Absent (an older gateway) reads
   * as off: that gateway only sent names to a page that asked, and this
   * page never asks.
   */
  labels?: boolean | null;
  nodes: { id?: string | null; name?: string | null; type?: string | null; degree?: number | null }[];
  edges: { src?: string | null; dst?: string | null; rel_type?: string | null }[];
  stats?: { node_count?: number; edge_count?: number } | null;
  /**
   * How many edges the gateway SENT versus how many exist between these
   * nodes. It caps them: the live display had 4,570 between 160 nodes,
   * which is neither drawable nor readable. Absent on a console talking to
   * a gateway from before the cap.
   */
  edges_drawn?: number | null;
  edges_total?: number | null;
  /**
   * WHY the node list is empty, when it is. Several situations produce the
   * same two empty arrays and only this tells them apart:
   *
   * - `empty_graph` — no entities. Nothing has been ingested.
   * - `below_min_degree` — entities exist, but none is connected enough to
   *   make the wall. A freshly ingested graph looks like this.
   * - `counts_unavailable` — the database would not say, so neither do we.
   *
   * The cluster-era reasons (`requires_intelligent_tier`, `no_clusters`,
   * `no_clusters_at_this_level`) are still handled: a display can be
   * newer than its gateway, and an unrecognised word is reported verbatim
   * rather than guessed around.
   *
   * Absent on an older gateway, which is why every reader treats missing as
   * unknown rather than as any one of them.
   */
  reason?: string | null;
  /** Entities in the graph — present alongside `reason`, and the number that
   * makes "not clustered" legible as distinct from "not ingested". */
  entity_count?: number | null;
}

export type SourceData = {
  cluster: SnapshotNode[];
  gpus: SnapshotGpu[];
  jobs: SnapshotJob[];
  scheduler: SnapshotScheduler;
  heartbeat: SnapshotHeartbeat;
  memory: SnapshotMemory;
  rag: SnapshotRag;
  graph: SnapshotGraph;
  /** The raw add-on map off the health endpoint: name → word. */
  addons: Record<string, string>;
};

// ── State ────────────────────────────────────────────────────────────────────

export interface Since {
  at: number;
  /** true = an event said so; false = we merely observed it from this moment. */
  exact: boolean;
}

export interface NodeState {
  id: string;
  hostname: string;
  status: NodeStatus;
  since: Since;
  /** backend → model, what it IS hosting. */
  running: Record<string, string>;
}

export interface GpuState {
  key: string;
  nodeId: string | null;
  hostname: string | null;
  name: string;
  util: number | null;
  vramUsed: number | null;
  vramTotal: number | null;
  temp: number | null;
  at: number;
  /** Set while utilisation has been ≥ PINNED_PCT without a break. */
  pinnedSince: Since | null;
}

export interface JobState {
  id: string;
  status: string;
  type: string | null;
  nodeId: string | null;
  createdAt: number | null;
}

export interface TaskState {
  task: string;
  ok: boolean;
  error: string | null;
  at: number;
}

export interface Transition {
  at: number;
  /** A stable key so React can list them; the event id when there was one. */
  key: string;
  text: string;
  severity: 'info' | 'warn' | 'bad';
}

/** One entity on the wall. */
export interface GraphNodeState {
  id: string;
  /**
   * The entity's name — but ONLY while the controller's
   * `kiosk.graph_labels` is on, because otherwise the gateway never sent
   * one and this falls back to the id. Never assume this is a name.
   */
  name: string;
  /** `person`, `concept`, … — a bucket, not a name, so it is always sent. */
  type: string | null;
  /** Edges at this entity. Drives size on screen and the sort order. */
  degree: number;
  /** When this entity last gained connections, if we have seen it happen. */
  grewAt: number | null;
}

export interface GraphState {
  /** The gateway said this answer carries names (`SnapshotGraph.labels`). */
  labels: boolean;
  nodes: Record<string, GraphNodeState>;
  links: { src: string; dst: string }[];
  /** Edges between the entities shown, from the gateway's own stats. */
  edgeCount: number;
  /** Of those, how many the gateway actually sent — it caps them. */
  edgesDrawn: number;
  /** `SnapshotGraph.reason`, verbatim; null when the gateway did not send one. */
  reason: string | null;
  /**
   * Entities in the WHOLE graph, from the gateway. Distinct from
   * `Object.keys(nodes).length`, which is the page of hubs on the wall —
   * 160 of several thousand. Deriving one from the other would make the
   * two always agree and never be right.
   */
  gatewayEntityCount: number | null;
}

export interface IngestState {
  /** Exact, from `graph.delta` events; null until one arrives. */
  lastAt: number | null;
  /** Entities added by events since this display connected. A reload resets it, honestly. */
  addedSinceConnect: number;
}

export type StreamStatus = 'connecting' | 'live' | 'reconnecting' | 'auth';

export interface KioskState {
  /**
   * Any arrival at all — an event, a keepalive, a snapshot. This is the
   * CONNECTION's pulse: it drives the stale band, the five-minute reload
   * and the host watchdog's heartbeat, all of which ask "is this page
   * still attached to a gateway".
   */
  lastContact: number | null;
  /**
   * The last arrival that actually CARRIED SOMETHING: a recognised event
   * or a snapshot source landing. Keepalives do not count, and that
   * distinction is the whole point.
   *
   * These were one field. A keepalive every 15s kept resetting it, so the
   * band read "live · 3s since last data" beside a picture that was hours
   * old — and because the snapshot is fetched once per stream connection,
   * nothing refetched it, so the display sat there being confidently
   * wrong for as long as the connection held. The operator reclustered
   * twice and watched the screen agree with itself both times.
   *
   * A keepalive is evidence about the PIPE. Treating it as evidence about
   * the DATA is how a display earns trust it has not got.
   */
  lastData: number | null;
  keepaliveMs: number;
  stream: StreamStatus;
  /** Last 401/403 status, when stream === 'auth'. */
  authStatus: number | null;
  sources: Record<SourceKey, { at: number | null; error: string | null }>;
  nodes: Record<string, NodeState>;
  gpus: Record<string, GpuState>;
  jobs: Record<string, JobState>;
  scheduler: { running: boolean; paused: boolean; queueDepth: number | null; active: number | null; error: string | null } | null;
  heartbeat: { enabled: boolean; running: boolean } | null;
  memory: { grade: string | null; warnings: string[]; error: string | null } | null;
  rag: { started: boolean; unembedded: number | null; docs: number | null } | null;
  tasks: Record<string, TaskState>;
  transitions: Transition[];
  graph: GraphState | null;
  /** The add-on map from the health endpoint, narrowed to words we render. */
  addons: Record<string, AddonWord>;
  ingest: IngestState;
}

export const PINNED_PCT = 90;
/** A cluster that grew within this window pulses on the graph view. */
export const RECENT_GROWTH_MS = 5 * 60_000;
export const DEFAULT_KEEPALIVE_MS = 15_000;
export const MAX_TRANSITIONS = 12;
/** Past this, the page reloads itself: one mechanism for a dead stream, an expired credential and a restarted gateway (§6.1). */
export const RELOAD_AFTER_MS = 5 * 60_000;
/** The band goes red at this many missed keepalives. */
export const STALE_KEEPALIVES = 3;
/**
 * A healthy connection that has carried no DATA for this long gets its
 * snapshot re-fetched.
 *
 * This is the other half of the band's lie, and the half a label cannot
 * fix. The snapshot is fetched once per stream CONNECTION, so on a link
 * that never drops, nothing ever refetches: the operator reclustered
 * twice and the display showed neither result, because from the page's
 * point of view nothing had happened. Naming the staleness honestly is
 * necessary; bounding it is what makes the screen right again.
 *
 * Not a poll. A poll fires on a busy cluster too; this fires only when
 * the stream has gone quiet, which on a working system it does not.
 */
export const REFRESH_DATA_AFTER_MS = 2 * 60_000;

const emptySources = (): KioskState['sources'] =>
  Object.fromEntries(SOURCES.map((k) => [k, { at: null, error: null }])) as KioskState['sources'];

export function initial(): KioskState {
  return {
    lastContact: null,
    lastData: null,
    keepaliveMs: DEFAULT_KEEPALIVE_MS,
    stream: 'connecting',
    authStatus: null,
    sources: emptySources(),
    nodes: {},
    gpus: {},
    jobs: {},
    scheduler: null,
    heartbeat: null,
    memory: null,
    rag: null,
    tasks: {},
    transitions: [],
    graph: null,
    addons: {},
    ingest: { lastAt: null, addedSinceConnect: 0 },
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

export function nodeStatus(raw: unknown): NodeStatus {
  return raw === 'online' || raw === 'busy' || raw === 'offline' ? raw : 'unknown';
}

export function addonWord(raw: unknown): AddonWord {
  return raw === 'enabled' || raw === 'disabled' || raw === 'unlicensed' || raw === 'unhealthy' ? raw : 'unknown';
}

const gpuKey = (g: { node_id?: string | null; hostname?: string | null; name?: string | null; index?: string | number | null }) =>
  `${g.node_id ?? g.hostname ?? g.name ?? '?'}/${g.index ?? 0}`;

function parseTs(v: unknown, fallback: number): number {
  if (typeof v !== 'string') return fallback;
  const t = Date.parse(v);
  return Number.isNaN(t) ? fallback : t;
}

function pushTransition(state: KioskState, t: Transition): KioskState {
  return { ...state, transitions: [t, ...state.transitions].slice(0, MAX_TRANSITIONS) };
}

const severityFor = (s: NodeStatus): Transition['severity'] =>
  s === 'offline' ? 'bad' : s === 'unknown' ? 'warn' : 'info';

// ── Snapshot ─────────────────────────────────────────────────────────────────

/** A source fetched successfully. Snapshot-detected changes get observed (not exact) `since`. */
export function applySource<K extends SourceKey>(state: KioskState, key: K, data: SourceData[K], now: number): KioskState {
  let next: KioskState = {
    ...state,
    lastContact: now,
    lastData: now,
    sources: { ...state.sources, [key]: { at: now, error: null } },
  };
  switch (key) {
    case 'cluster': {
      const nodes: Record<string, NodeState> = {};
      for (const n of data as SnapshotNode[]) {
        if (!n.id && !n.hostname) continue;
        const id = n.id || n.hostname!;
        const status = nodeStatus(n.status);
        const prev = state.nodes[id];
        const same = prev && prev.status === status;
        nodes[id] = {
          id,
          hostname: n.hostname || id,
          status,
          since: same ? prev.since : { at: now, exact: false },
          running: n.running_backends ?? {},
        };
        if (prev && !same) {
          next = pushTransition(next, {
            at: now,
            key: `snap-${id}-${now}`,
            text: `${nodes[id].hostname} ${prev.status} → ${status} (noticed on refresh)`,
            severity: severityFor(status),
          });
        }
      }
      next.nodes = nodes;
      break;
    }
    case 'gpus': {
      const gpus: Record<string, GpuState> = {};
      for (const g of data as SnapshotGpu[]) {
        const key = gpuKey(g);
        const prev = state.gpus[key];
        const util = num(g.utilization);
        gpus[key] = {
          key,
          nodeId: g.node_id ?? null,
          hostname: g.hostname ?? null,
          name: g.name || 'GPU',
          util,
          vramUsed: num(g.memory_used),
          vramTotal: num(g.memory_total),
          temp: num(g.temperature),
          at: now,
          pinnedSince: pinned(prev?.pinnedSince ?? null, util, { at: now, exact: false }),
        };
      }
      next.gpus = gpus;
      break;
    }
    case 'jobs': {
      const jobs: Record<string, JobState> = {};
      for (const j of data as SnapshotJob[]) {
        if (!j.job_id) continue;
        const status = j.status ?? 'unknown';
        // Terminal jobs are history, not work.
        if (status === 'completed' || status === 'cancelled') continue;
        jobs[j.job_id] = {
          id: j.job_id,
          status,
          type: j.type ?? null,
          nodeId: j.node_id ?? null,
          createdAt: j.created_at ? parseTs(j.created_at, now) : null,
        };
      }
      next.jobs = jobs;
      break;
    }
    case 'scheduler': {
      const s = data as SnapshotScheduler;
      next.scheduler = {
        running: s.running ?? false,
        paused: s.paused ?? false,
        queueDepth: num(s.queue_depth),
        active: num(s.active_jobs),
        error: s.error ?? null,
      };
      break;
    }
    case 'heartbeat': {
      const h = data as SnapshotHeartbeat;
      next.heartbeat = { enabled: h.enabled ?? false, running: h.running ?? false };
      break;
    }
    case 'memory': {
      const m = data as SnapshotMemory;
      next.memory = { grade: m.grade ?? null, warnings: m.warnings ?? [], error: m.error ?? null };
      break;
    }
    case 'rag': {
      const r = data as SnapshotRag;
      next.rag = { started: r.started ?? false, unembedded: num(r.unembedded_chunks), docs: num(r.doc_count) };
      break;
    }
    case 'graph': {
      const g = data as SnapshotGraph;
      const nodes: Record<string, GraphNodeState> = {};
      // A refreshed snapshot showing an entity with MORE EDGES than before
      // is an ingest, seen late: treat it as one — pulse, push-in, counters
      // — so growth reacts on screen whether it arrives as a `graph.delta`
      // event, on a reconnect, or on a refresh. Snapshot-detected, so the
      // time is when we noticed, not when it happened.
      //
      // At cluster level this counted new MEMBERS. Degree is the entity-level
      // equivalent and is the honest one: an ingest that links an entity to
      // something new is exactly what a knowledge display should react to.
      // An entity appearing for the first time is not counted as growth —
      // the first snapshot would otherwise read as one enormous ingest.
      let gained = 0;
      let grew = 0;
      // Names only on the gateway's say-so. A `name` arriving without
      // `labels: true` is not drawn: the marker on screen and the names on
      // screen must never disagree.
      const labels = g.labels === true;
      for (const n of g.nodes ?? []) {
        if (!n.id) continue;
        const prev = state.graph?.nodes[n.id];
        // Sim input (mass), not a displayed measurement: absent degree lays out as 0.
        const degree = num(n.degree) ?? 0;
        const gain = prev ? degree - prev.degree : 0;
        if (gain > 0) {
          gained += gain;
          grew++;
        }
        nodes[n.id] = {
          id: n.id,
          // No `name` on the wire is the DEFAULT, not a failure: the
          // gateway withholds it unless the operator switched names on.
          // The id is what is left, and it is a UUID.
          name: labels ? n.name || n.id : n.id,
          type: n.type ?? null,
          degree,
          grewAt: gain > 0 ? now : (prev?.grewAt ?? null),
        };
      }
      if (gained > 0) {
        next.ingest = { lastAt: now, addedSinceConnect: state.ingest.addedSinceConnect + gained };
        next = pushTransition(next, {
          at: now,
          key: `snap-graph-${now}`,
          text: `ingest +${gained} link${gained === 1 ? '' : 's'} · ${grew} entit${grew === 1 ? 'y' : 'ies'} grew (noticed on refresh)`,
          severity: 'info',
        });
      }
      const links = (g.edges ?? [])
        .filter((e) => e.src && e.dst && nodes[e.src] && nodes[e.dst])
        .map((e) => ({ src: e.src!, dst: e.dst! }));
      next.graph = {
        labels,
        nodes,
        links,
        edgeCount: g.edges_total ?? g.stats?.edge_count ?? links.length,
        edgesDrawn: g.edges_drawn ?? links.length,
        reason: g.reason ?? null,
        gatewayEntityCount: num(g.entity_count),
      };
      break;
    }
    case 'addons': {
      const raw = data as Record<string, string>;
      next.addons = Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, addonWord(v)]));
      break;
    }
  }
  return next;
}

/** A source failed. Its last-good data stays on screen, aged; the cell says so. */
export function applySourceError(state: KioskState, key: SourceKey, error: string, now: number): KioskState {
  void now;
  return { ...state, sources: { ...state.sources, [key]: { at: state.sources[key].at, error } } };
}

function pinned(prev: Since | null, util: number | null, whenStarted: Since): Since | null {
  if (util == null || util < PINNED_PCT) return null;
  return prev ?? whenStarted;
}

// ── Stream ───────────────────────────────────────────────────────────────────

/**
 * A keepalive proves the pipe is open and NOTHING else. It must not touch
 * `lastData` — see the field's comment. This is the line that made the
 * band lie.
 */
export function noteKeepalive(state: KioskState, now: number): KioskState {
  return { ...state, lastContact: now };
}

export function noteStream(state: KioskState, stream: StreamStatus, authStatus: number | null = null): KioskState {
  return { ...state, stream, authStatus };
}

/**
 * Stream events this store renders. Anything not here arrived, but changed
 * nothing on screen, so it is contact and not data.
 */
export const DATA_EVENTS = [
  'node.state',
  'gpu.sample',
  'job.state',
  'scheduler.state',
  'graph.delta',
  'heartbeat.task',
] as const;

/** One event off the stream. Unknown event names are ignored; malformed data is ignored. */
export function applyEvent(state: KioskState, ev: StreamEvent, now: number): KioskState {
  let d: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(ev.data);
    // Something arrived, so the pipe is open; it carried nothing we can
    // read, so it is not data.
    if (!parsed || typeof parsed !== 'object') return { ...state, lastContact: now };
    d = parsed as Record<string, unknown>;
  } catch {
    return { ...state, lastContact: now };
  }
  const ts = parseTs(d.ts, now);
  const key = ev.id ?? `${ev.event}-${ts}`;
  // Only an event this store actually RENDERS counts as data.
  //
  // `hello` is a handshake — it announces the keepalive interval and says
  // nothing about the cluster, so counting it would let every reconnect
  // reset the freshness clock without one fact arriving. An unrecognised
  // event name is the same case a year later: the gateway grew a new
  // event, this page ignores it, and the picture on the wall did not
  // change. An allow-list keeps that honest by construction; a deny-list
  // of one name would not have.
  const carriesData = (DATA_EVENTS as readonly string[]).includes(ev.event);
  let next: KioskState = {
    ...state,
    lastContact: now,
    lastData: carriesData ? now : state.lastData,
  };

  switch (ev.event) {
    case 'hello': {
      const k = num(d.keepalive_ms);
      if (k && k > 0) next.keepaliveMs = k;
      break;
    }
    case 'node.state': {
      const id = String(d.node_id ?? d.hostname ?? '');
      if (!id) break;
      const status = nodeStatus(d.status);
      const prev = state.nodes[id];
      const hostname = String(d.hostname ?? prev?.hostname ?? id);
      if (prev && prev.status === status) break;
      next.nodes = {
        ...state.nodes,
        [id]: { id, hostname, status, since: { at: ts, exact: true }, running: prev?.running ?? {} },
      };
      next = pushTransition(next, {
        at: ts,
        key,
        text: `${hostname} ${prev?.status ?? String(d.previous ?? '?')} → ${status}`,
        severity: severityFor(status),
      });
      break;
    }
    case 'gpu.sample': {
      const g: SnapshotGpu = d as SnapshotGpu;
      const k = gpuKey(g);
      const prev = state.gpus[k];
      const util = num(g.utilization);
      next.gpus = {
        ...state.gpus,
        [k]: {
          key: k,
          nodeId: g.node_id ?? prev?.nodeId ?? null,
          hostname: g.hostname ?? prev?.hostname ?? null,
          name: g.name || prev?.name || 'GPU',
          util,
          vramUsed: num(g.memory_used) ?? prev?.vramUsed ?? null,
          vramTotal: num(g.memory_total) ?? prev?.vramTotal ?? null,
          temp: num(g.temperature) ?? prev?.temp ?? null,
          at: ts,
          pinnedSince: pinned(prev?.pinnedSince ?? null, util, { at: ts, exact: true }),
        },
      };
      break;
    }
    case 'job.state': {
      const id = String(d.job_id ?? '');
      if (!id) break;
      const status = String(d.status ?? 'unknown');
      const jobs = { ...state.jobs };
      if (status === 'completed' || status === 'cancelled') {
        delete jobs[id];
      } else {
        const prev = state.jobs[id];
        jobs[id] = {
          id,
          status,
          type: (d.type as string | undefined) ?? prev?.type ?? null,
          nodeId: (d.node_id as string | undefined) ?? prev?.nodeId ?? null,
          createdAt: prev?.createdAt ?? ts,
        };
      }
      next.jobs = jobs;
      if (status === 'failed') {
        const why = typeof d.error === 'string' && d.error ? ` — ${d.error}` : '';
        next = pushTransition(next, {
          at: ts,
          key,
          text: `job ${id.slice(0, 12)} failed${d.node_id ? ` on ${String(d.node_id)}` : ''}${why}`,
          severity: 'bad',
        });
      }
      break;
    }
    case 'scheduler.state': {
      const prev = state.scheduler;
      const running = typeof d.running === 'boolean' ? d.running : (prev?.running ?? false);
      const paused = typeof d.paused === 'boolean' ? d.paused : (prev?.paused ?? false);
      next.scheduler = {
        running,
        paused,
        queueDepth: num(d.queue_depth) ?? prev?.queueDepth ?? null,
        active: num(d.active_jobs) ?? prev?.active ?? null,
        error: prev?.error ?? null,
      };
      if (prev && (prev.paused !== paused || prev.running !== running)) {
        const word = !running ? 'stopped' : paused ? 'paused' : 'running';
        next = pushTransition(next, { at: ts, key, text: `scheduler ${word}`, severity: word === 'running' ? 'info' : 'warn' });
      }
      break;
    }
    case 'graph.delta': {
      // An ingest landed: some entities, some edges.
      //
      // `clusters: [{id, member_count}]` used to be read here and is now
      // ignored. Those are CLUSTER ids and the wall holds ENTITY ids, so
      // the old loop could only miss — or, worse, it created an entry for
      // any id it did not recognise, which would put a phantom node on the
      // screen with a degree of zero. The proposed contract reached the
      // same conclusion for the gateway's side: ship the two counts, leave
      // `clusters` out until there is an incremental assignment path.
      //
      // The counts are the part that is true on every tier and moves on
      // every ingest, which is the whole reason this view is entity-level.
      const added = num(d.entities_added) ?? 0;
      const g = state.graph;
      if (g) {
        next.graph = { ...g, edgeCount: g.edgeCount + (num(d.edges_added) ?? 0) };
      }
      next.ingest = { lastAt: ts, addedSinceConnect: state.ingest.addedSinceConnect + added };
      if (added > 0) {
        next = pushTransition(next, {
          at: ts,
          key,
          text: `ingest +${added} entit${added === 1 ? 'y' : 'ies'}`,
          severity: 'info',
        });
      }
      break;
    }
    case 'heartbeat.task': {
      const task = String(d.task ?? '');
      if (!task) break;
      const ok = d.ok === true;
      const error = typeof d.error === 'string' ? d.error : null;
      const prev = state.tasks[task];
      next.tasks = { ...state.tasks, [task]: { task, ok, error, at: ts } };
      if (!ok) {
        next = pushTransition(next, { at: ts, key, text: `task ${task} failed${error ? ` — ${error}` : ''}`, severity: 'bad' });
      } else if (prev && !prev.ok) {
        next = pushTransition(next, { at: ts, key, text: `task ${task} recovered`, severity: 'info' });
      }
      break;
    }
    default:
      break;
  }
  return next;
}

// ── Selectors: what the screen shows ─────────────────────────────────────────

export interface Liveness {
  /** ms since anything arrived — event, keepalive or snapshot. The CONNECTION's age. */
  contactAgeMs: number | null;
  /** ms since something arrived that changed the picture. The age of what is ON SCREEN. */
  dataAgeMs: number | null;
  /** Red past this. Derived from the keepalive, not a magic number. */
  thresholdMs: number;
  /** The connection has missed its keepalives. */
  stale: boolean;
  /** Past RELOAD_AFTER_MS — the hook reloads the page. */
  dead: boolean;
  /**
   * Connected, but what is on screen is older than REFRESH_DATA_AFTER_MS.
   * The hook re-fetches the snapshot on this; the band says so meanwhile.
   */
  dataStale: boolean;
}

/**
 * Should the page re-fetch its snapshot right now?
 *
 * Pure, because it is a judgement and judgements get tested. The hook
 * calls it once a second and owns only the wiring.
 *
 * Three conditions, and the two negative ones are the load-bearing half:
 *  - the picture is older than the window, and
 *  - the CONNECTION is healthy — a disconnected stream already refetches
 *    on the way back up, and firing here too would hammer a gateway that
 *    is down, which is when it can least afford it, and
 *  - we have not just done this — otherwise every tick after the window
 *    fires another fetch, once a second, forever.
 */
export function shouldRefreshData(state: KioskState, now: number, lastRefreshAt: number): boolean {
  const l = liveness(state, now);
  return l.dataStale && !l.stale && now - lastRefreshAt > REFRESH_DATA_AFTER_MS;
}

export function liveness(state: KioskState, now: number): Liveness {
  const age = (at: number | null) => (at == null ? null : Math.max(0, now - at));
  const contactAgeMs = age(state.lastContact);
  const dataAgeMs = age(state.lastData);
  const thresholdMs = state.keepaliveMs * STALE_KEEPALIVES;
  return {
    contactAgeMs,
    dataAgeMs,
    thresholdMs,
    // Connection health, from contact. Unchanged: a keepalive is exactly
    // the evidence this question wants.
    stale: contactAgeMs != null && contactAgeMs > thresholdMs,
    dead: contactAgeMs != null && contactAgeMs > RELOAD_AFTER_MS,
    // Freshness of the PICTURE. `dataAgeMs == null` with contact
    // established means connected and nothing has ever landed, which is
    // just as stale.
    dataStale: contactAgeMs != null && (dataAgeMs == null || dataAgeMs > REFRESH_DATA_AFTER_MS),
  };
}

const STATUS_RANK: Record<NodeStatus, number> = { offline: 0, unknown: 1, busy: 2, online: 3 };

/** Fleet, attention first: a node down outranks everything else on the screen. */
export function fleet(state: KioskState): NodeState[] {
  return Object.values(state.nodes).sort(
    (a, b) => STATUS_RANK[a.status] - STATUS_RANK[b.status] || a.hostname.localeCompare(b.hostname),
  );
}

/** GPUs, hottest first. */
export function pressure(state: KioskState): GpuState[] {
  return Object.values(state.gpus).sort((a, b) => (b.util ?? -1) - (a.util ?? -1) || a.key.localeCompare(b.key));
}

export interface Work {
  queueDepth: number | null;
  active: number | null;
  /** Age of the oldest job still waiting — "depth 3 with a 40-minute head is a stuck scheduler". */
  oldestWaitingMs: number | null;
  schedulerWord: 'running' | 'paused' | 'stopped' | 'unknown';
}

export function work(state: KioskState, now: number): Work {
  const queued = Object.values(state.jobs).filter((j) => j.status === 'queued' || j.status === 'pending');
  const running = Object.values(state.jobs).filter((j) => j.status === 'running');
  const oldest = queued.reduce<number | null>((m, j) => (j.createdAt == null ? m : m == null ? j.createdAt : Math.min(m, j.createdAt)), null);
  const s = state.scheduler;
  return {
    queueDepth: s?.queueDepth ?? (state.sources.jobs.at ? queued.length : null),
    active: s?.active ?? (state.sources.jobs.at ? running.length : null),
    oldestWaitingMs: oldest == null ? null : Math.max(0, now - oldest),
    schedulerWord: !s ? 'unknown' : !s.running ? 'stopped' : s.paused ? 'paused' : 'running',
  };
}

export interface Exception {
  key: string;
  text: string;
  /** When it started, if known. */
  since: number | null;
  severity: 'warn' | 'bad';
}

/** Present only when abnormal — the region collapses to nothing otherwise (the wallpaper rule). */
export function exceptions(state: KioskState, now: number): Exception[] {
  const out: Exception[] = [];
  for (const t of Object.values(state.tasks)) {
    if (!t.ok) out.push({ key: `task:${t.task}`, text: `${t.task} failing${t.error ? ` — ${t.error}` : ''}`, since: t.at, severity: 'bad' });
  }
  const s = state.scheduler;
  if (s && !s.running) out.push({ key: 'sched', text: 'scheduler stopped', since: null, severity: 'bad' });
  else if (s?.paused) out.push({ key: 'sched', text: 'scheduler paused', since: null, severity: 'warn' });
  if (s?.error) out.push({ key: 'sched-err', text: `scheduler: ${s.error}`, since: null, severity: 'bad' });
  const h = state.heartbeat;
  if (h && h.enabled && !h.running) out.push({ key: 'hb', text: 'heartbeat loop enabled but not running', since: null, severity: 'bad' });
  const m = state.memory;
  if (m?.error) out.push({ key: 'mem', text: `memory: ${m.error}`, since: null, severity: 'bad' });
  else if (m && (m.grade === 'D' || m.grade === 'F')) out.push({ key: 'mem', text: `memory grade ${m.grade}${m.warnings[0] ? ` — ${m.warnings[0]}` : ''}`, since: null, severity: 'warn' });
  const r = state.rag;
  if (r && !r.started && r.docs !== null && r.docs > 0) out.push({ key: 'rag', text: 'RAG not started', since: null, severity: 'warn' });
  for (const k of SOURCES) {
    const src = state.sources[k];
    if (src.error) {
      out.push({
        key: `src:${k}`,
        text: src.at ? `${k} · ${fmtDuration(now - src.at)} stale` : `${k} · never loaded`,
        since: src.at,
        severity: 'warn',
      });
    }
  }
  return out;
}

// ── Graph view ───────────────────────────────────────────────────────────────

export interface GraphView {
  /** Most-connected first. */
  nodes: GraphNodeState[];
  links: GraphState['links'];
  /** Entities in the whole graph, from the gateway — not `nodes.length`. */
  gatewayEntityCount: number | null;
  /** Edges between the entities shown. */
  edgeCount: number | null;
  /** How many of those are actually on screen; the gateway caps them. */
  edgesDrawn: number | null;
  addedSinceConnect: number;
  /** ms since the last ingest event; null if none has arrived. */
  lastIngestMs: number | null;
  /** Entity ids that gained connections within RECENT_GROWTH_MS. */
  recentlyGrown: Set<string>;
  /** The knowledge pack's state — 'unknown' until /health has answered. */
  trellion: AddonWord;
  /**
   * The Intelligent tier's state.
   *
   * It no longer gates whether this screen has anything to SHOW — that was
   * the point of moving to the entity level, which is built from `entities`
   * and `edges` and needs no clustering. It is kept because it still
   * explains what the graph LOOKS like: the open tier writes two edge
   * types and every edge means the same thing, while the Intelligent tier's
   * relation extractor gives them kinds. The strip says which the viewer
   * is looking at rather than leaving a flat graph looking broken.
   */
  intel: AddonWord;
  /** Why the entity list is empty, from the gateway. Null on an older one. */
  reason: string | null;
  /**
   * The controller has entity names switched on and this display is
   * showing them. Drives the names AND the `LABELS ON` marker, from one
   * value, so the two cannot disagree.
   */
  labels: boolean;
  loaded: boolean;
}

export function graphView(state: KioskState, now: number): GraphView {
  const g = state.graph;
  // By degree, because that is what size on screen means now. It used to be
  // by member count, and `structureKey` exists because sorting by a number
  // that moves on every ingest rebuilt the whole simulation each time —
  // degree moves too, so that guard still earns its place.
  const nodes = g ? Object.values(g.nodes).sort((a, b) => b.degree - a.degree || a.id.localeCompare(b.id)) : [];
  return {
    nodes,
    links: g?.links ?? [],
    gatewayEntityCount: g?.gatewayEntityCount ?? null,
    edgeCount: g?.edgeCount ?? null,
    edgesDrawn: g?.edgesDrawn ?? null,
    addedSinceConnect: state.ingest.addedSinceConnect,
    lastIngestMs: state.ingest.lastAt == null ? null : Math.max(0, now - state.ingest.lastAt),
    recentlyGrown: new Set(nodes.filter((n) => n.grewAt != null && now - n.grewAt <= RECENT_GROWTH_MS).map((n) => n.id)),
    trellion: state.sources.addons.at ? (state.addons.trellion ?? 'unknown') : 'unknown',
    intel: state.sources.addons.at ? (state.addons.trellion_intel ?? 'unknown') : 'unknown',
    reason: g?.reason ?? null,
    labels: g?.labels ?? false,
    loaded: !!g,
  };
}

// ── Formatting ───────────────────────────────────────────────────────────────

/** "42s", "12m", "3h 12m", "2d 4h". Legible at three metres; no decimals. */
export function fmtDuration(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}

/** A duration with its provenance: "12m" when an event said so, "≥ 12m" when we only watched. */
export function fmtSince(since: Since, now: number): string {
  const d = fmtDuration(now - since.at);
  return since.exact ? d : `≥ ${d}`;
}
