// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The kiosk's data loop: snapshot on connect, then the stream, plus the three
// liveness obligations from an earlier change — self-heal, render the signal,
// publish the heartbeat.
//
// Two values drive it, not one. `lastContact` is the connection's pulse
// (keepalives count) and owns the watchdog heartbeat and the reload;
// `lastData` is the age of what is on screen (keepalives do NOT count) and
// owns the band. See the store's field comments for why they were split.
//
// No TanStack Query, no polling. The snapshot is fetched once per stream
// connection (an earlier change mechanism 3: "cheap, because reconnects are rare");
// everything after that arrives as events — with one self-heal, below, for
// the case that assumption does not cover: a connection that never drops and
// carries nothing.

import { useEffect, useRef, useState } from 'react';
import { createEventStream, type MetisClient } from '@metis/api';
import {
  initial,
  applySource,
  applySourceError,
  applyEvent,
  noteKeepalive,
  noteStream,
  liveness,
  DEFAULT_KEEPALIVE_MS,
  STALE_KEEPALIVES,
  shouldRefreshData,
  HEALTH_SOURCES,
  type KioskState,
  type SourceKey,
  type SourceData,
} from './store';

export interface KioskDeps {
  client: MetisClient;
  /** Optional — see KioskShellProps. Absent means the transport carries no Authorization header, which is the kiosk's normal state. */
  getToken?: () => string | null;
  /** Which snapshot sources this view needs. The stream is shared by all views. */
  sources?: readonly SourceKey[];
  /**
   * Re-fetch a subset of sources on an interval. Off by default and meant to
   * stay off: the design is snapshot-then-stream, and a
   * poll is the thing that design exists to avoid. It is here for one
   * reason — until the gateway serves `graph.delta`, it is the only way the
   * graph view can react to an ingest at all, and a demo needs that.
   */
  poll?: { everyMs: number; sources: readonly SourceKey[] };
  /** Injected so tests can assert the reload without a page. */
  reload?: () => void;
  /** Where the host watchdog reads the heartbeat (§6.3). */
  publishHeartbeat?: (at: number) => void;
}

export const STREAM_PATH = '/api/events/stream';

/**
 * How long after a 401/403 on the stream the page tries again. The stream
 * client never retries an auth failure on its own, because for a person
 * that means "logged out". On a display it does not: the local proxy holds
 * the credential and re-mints it, so a refusal during a renewal or a proxy
 * restart is transient. Without a retry the band said "credential rejected"
 * forever while the polled tiles kept updating underneath it.
 */
export const AUTH_RETRY_MS = 30_000;

declare global {
  interface Window {
    /**
   * Set on every ARRIVAL — never on a timer. The CDP watchdog reads it to
   * answer "is this browser still attached and running JavaScript", which
   * a keepalive answers honestly. It is deliberately not the band's
   * number: the watchdog asks about the page, the band asks about the data.
   */
    __nooKioskHeartbeat?: number;
  }
}

const defaultPublish = (at: number) => {
  if (typeof window !== 'undefined') window.__nooKioskHeartbeat = at;
};
const defaultReload = () => {
  if (typeof location !== 'undefined') location.reload();
};

/** Fetch a view's contracted sources; each lands independently so one failure ages one cell. */
async function snapshot(
  client: MetisClient,
  sources: readonly SourceKey[],
  apply: <K extends SourceKey>(k: K, d: SourceData[K]) => void,
  fail: (k: SourceKey, e: string) => void,
) {
  const errOf = (r: { error?: unknown; response?: Response }) =>
    r.response && !r.response.ok ? `HTTP ${r.response.status}` : r.error ? String((r.error as { detail?: string }).detail ?? 'error') : null;
  const want = new Set(sources);
  const guard = async <K extends SourceKey>(k: K, run: () => Promise<{ data?: unknown; error?: unknown; response?: Response }>, pick: (d: never) => SourceData[K]) => {
    if (!want.has(k)) return;
    try {
      const r = await run();
      const e = errOf(r);
      if (e || r.data == null) fail(k, e ?? 'empty');
      else apply(k, pick(r.data as never));
    } catch (e) {
      fail(k, e instanceof Error ? e.message : 'network');
    }
  };
  await Promise.all([
    guard('cluster', () => client.GET('/api/cluster/status'), (d: { nodes?: SourceData['cluster'] | null }) =>
      (d.nodes ?? []).map((n) => ({ ...n, id: n.id ?? '' })),
    ),
    guard('gpus', () => client.GET('/api/cluster/gpu-metrics'), (d: { gpus?: SourceData['gpus'] | null }) => d.gpus ?? []),
    guard('jobs', () => client.GET('/api/jobs'), (d: { jobs?: Array<Partial<SourceData['jobs'][number]>> | null }) =>
      (d.jobs ?? []).filter((j) => !!j.job_id).map((j) => ({ ...j, job_id: j.job_id! })),
    ),
    guard('scheduler', () => client.GET('/api/scheduler/status'), (d: SourceData['scheduler']) => d),
    guard('heartbeat', () => client.GET('/api/heartbeat/status'), (d: SourceData['heartbeat']) => d),
    guard('memory', () => client.GET('/api/memory/health'), (d: { overall?: { grade?: string }; conversation_memory?: { warnings?: string[]; error?: string } }) => ({
      grade: d.overall?.grade ?? null,
      warnings: d.conversation_memory?.warnings ?? [],
      error: d.conversation_memory?.error ?? null,
    })),
    guard('rag', () => client.GET('/api/v1/rag/status'), (d: SourceData['rag']) => d),
    // The graph view, through the KIOSK PROJECTION — not the general
    // route.
    //
    // This read `/api/v1/graph/clusters/overview` and showed 58 nodes and
    // zero links on the first real display: clustering covered 761 of
    // 4,538 entities and the cluster-edge query needs two shared edges with
    // both endpoints already clustered. It could not react either, since
    // clusters move on a recluster and not on an ingest.
    //
    // `/api/kiosk/graph` serves the entity level, which every tier writes
    // and every ingest moves — and it is a projection, so the gateway
    // decides at FETCH time whether a name goes on the wire. That matters
    // more here than it did at cluster level, not less: an entity name is a
    // person or a document, and this is a screen in a hallway. Unless the
    // operator has switched `kiosk.graph_labels` on at the controller, no
    // name reaches this code to be rendered, cached or read out of
    // devtools — and nothing this page sends can switch it on.
    guard('graph', () => client.GET('/api/kiosk/graph'), (d: SourceData['graph']) => ({
      labels: d.labels === true,
      nodes: d.nodes ?? [],
      edges: d.edges ?? [],
      stats: d.stats ?? null,
      reason: d.reason ?? null,
      entity_count: d.entity_count ?? null,
    })),
    // The add-on map, from the endpoint built to serve it. NOT `/health`:
    // that answers anyone on the tailnet with no credential at all, and
    // carries the gateway version, the engine name, the peer count and the
    // dependency health beside the four words this tile wants. Reading the
    // credentialed route keeps the display's reach the size of its job.
    guard('addons', () => client.GET('/api/kiosk/addons'), (d: { addons?: Record<string, string> | null }) => d.addons ?? {}),
  ]);
}

export function useKiosk(deps: KioskDeps): { state: KioskState; now: number } {
  const { client, getToken, sources = HEALTH_SOURCES, poll, reload = defaultReload, publishHeartbeat = defaultPublish } = deps;
  const [state, setState] = useState<KioskState>(initial);
  const [now, setNow] = useState(() => Date.now());
  const ref = useRef(state);
  ref.current = state;
  const reloaded = useRef(false);
  const lastDataRefresh = useRef(0);

  useEffect(() => {
    let alive = true;
    const update = (f: (s: KioskState, now: number) => KioskState) => {
      if (!alive) return;
      const t = Date.now();
      const next = f(ref.current, t);
      if (next.lastContact !== ref.current.lastContact && next.lastContact != null) {
        publishHeartbeat(next.lastContact);
      }
      ref.current = next;
      setState(next);
    };

    const refresh = (which: readonly SourceKey[] = sources) =>
      snapshot(
        client,
        which,
        (k, d) => update((s, t) => applySource(s, k, d, t)),
        (k, e) => update((s, t) => applySourceError(s, k, e, t)),
      );
    const pollTimer = poll && poll.everyMs > 0 ? setInterval(() => void refresh(poll.sources), poll.everyMs) : null;

    // Snapshot immediately, so a gateway that has no stream yet still shows
    // something; then once per (re)connection, so a reconnect after an outage
    // restores correct state rather than pre-disconnect state (§9 test 6).
    let opens = 0;
    let authRetry: ReturnType<typeof setTimeout> | null = null;
    void refresh();
    const stream = createEventStream(STREAM_PATH, {
      baseUrl: '',
      getToken,
      // The band goes red at this many missed keepalives; the reader gives
      // up on the connection at the same point, so a proxy holding a dead
      // stream open costs one threshold, not the five-minute reload.
      stallMs: DEFAULT_KEEPALIVE_MS * STALE_KEEPALIVES,
      onOpen: () => {
        update((s) => noteStream(s, 'live'));
        if (opens++ > 0) void refresh();
      },
      onEvent: (ev) => {
        update((s, t) => applyEvent(s, ev, t));
        // `hello` may have changed the announced keepalive.
        stream.setStallMs(ref.current.keepaliveMs * STALE_KEEPALIVES);
      },
      onKeepalive: () => update((s, t) => noteKeepalive(s, t)),
      onError: () => update((s) => noteStream(s, 'reconnecting')),
      onAuthFail: (status) => {
        update((s) => noteStream(s, 'auth', status));
        if (!authRetry) {
          authRetry = setTimeout(() => {
            authRetry = null;
            stream.reconnectNow();
          }, AUTH_RETRY_MS);
        }
      },
    });

    // The ticking clock: re-renders durations and the band once a second, and
    // owns the one self-heal. Reload only once the page has ever had data —
    // a gateway that is down at boot should show "waiting", not reload-loop.
    const tick = setInterval(() => {
      const t = Date.now();
      setNow(t);
      if (!reloaded.current && liveness(ref.current, t).dead) {
        reloaded.current = true;
        reload();
      }
      // A connection that holds open and carries nothing is the case the
      // snapshot-then-stream design does not cover: the snapshot is
      // fetched once per CONNECTION, so on a link that never drops,
      // nothing ever refetches. The operator reclustered twice and the
      // display showed neither result while insisting it was live.
      //
      // So: bound it. Re-fetch when the stream has been quiet, at most
      // once per window, and never when it is merely disconnected —
      // `reconnecting` already refetches on the way back up, and firing
      // here as well would hammer a gateway that is down.
      else if (shouldRefreshData(ref.current, t, lastDataRefresh.current)) {
        lastDataRefresh.current = t;
        void refresh();
      }
    }, 1000);

    return () => {
      alive = false;
      clearInterval(tick);
      if (pollTimer) clearInterval(pollTimer);
      if (authRetry) clearTimeout(authRetry);
      stream.close();
    };
  }, [client, getToken, sources, poll, reload, publishHeartbeat]);

  return { state, now };
}

/** Burn-in drift: nudge the whole layout a few pixels on a slow timer (not in the proposal; a wall display is static for months). */
export function useBurnInDrift(everyMs = 60_000, maxPx = 6) {
  useEffect(() => {
    const root = document.documentElement;
    const nudge = () => {
      const r = () => `${Math.round((Math.random() * 2 - 1) * maxPx)}px`;
      root.style.setProperty('--k-shift-x', r());
      root.style.setProperty('--k-shift-y', r());
    };
    const id = setInterval(nudge, everyMs);
    return () => {
      clearInterval(id);
      root.style.removeProperty('--k-shift-x');
      root.style.removeProperty('--k-shift-y');
    };
  }, [everyMs, maxPx]);
}
