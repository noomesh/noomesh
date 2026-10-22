// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useEffect, useRef, useState } from 'react';
import { useAuth } from '@metis/core';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { meterLevel } from '@/lib/meter';
import { useObservability, type AddonState } from './useObservability';
import { groupBackendDoors, type ContainerRow } from './doorGroups';
import { useGrafanaSession, sendTab, type TabHandle } from './useGrafanaSession';
import {
  arrivalAsksForGrafana,
  clearArrival,
  lastAutoOpen,
  mayAutoOpen,
  recordAutoOpen,
} from './grafanaArrival';

const gb = (mb: number) => (mb / 1024).toFixed(1);

const ADDON_BADGE: Record<AddonState, string> = {
  enabled: 'on',
  disabled: 'off',
  unhealthy: 'down',
  unknown: '?',
};

/**
 * The wording carries the distinction the colour does: `disabled` is a choice,
 * `unhealthy` is a fault. Saying "not a fault" out loud on the disabled case is
 * the point — otherwise an operator reads any non-green pill as something to
 * fix.
 */
const ADDON_HINT: Record<AddonState, (label: string) => string> = {
  enabled: (l) => `${l} is enabled and healthy on this install.`,
  disabled: (l) =>
    `${l} is turned off on this install — not a fault. Enable it in the gateway's configuration.`,
  unhealthy: (l) =>
    `${l} is enabled but not responding — its container is missing or down. This one is a fault.`,
  unknown: (l) => `${l} reported a state this console does not recognise.`,
};

/**
 * "Open Grafana": a tab is opened SYNCHRONOUSLY on the click (so the popup
 * blocker leaves it alone), then the gateway mints a session for this
 * account and the tab is sent there. The gateway decides the Grafana role
 * from the LIVE account (admin→Admin, operator→Editor, user→Viewer) and
 * refuses a disabled one; the session lasts 5 minutes by default, after
 * which Grafana shows its login-disabled page and the fix is to click again.
 */
function OpenGrafana() {
  const mint = useGrafanaSession();
  const [note, setNote] = useState<string | null>(null);
  const { ready, isLoggedIn } = useAuth();
  // Arrived from a bookmark of Grafana (grafanaArrival.ts): once the
  // console's own login is satisfied, open Grafana in THIS tab — a
  // navigation, so no popup blocker is involved and the click path below
  // is unchanged. Once per arrival; a bounce straight back is not reopened.
  const [arrival] = useState(
    () => typeof window !== 'undefined' && arrivalAsksForGrafana(window.location.hash),
  );
  const arrived = useRef(false);
  useEffect(() => {
    if (!arrival || arrived.current || !ready || !isLoggedIn) return;
    arrived.current = true;
    clearArrival(window);
    const tab = () => window.sessionStorage;
    const now = Date.now();
    if (!mayAutoOpen(lastAutoOpen(tab), now)) {
      setNote('Grafana sent this tab straight back without a session, so it was not reopened automatically — click Open Grafana.');
      return;
    }
    recordAutoOpen(tab, now);
    mint
      .mutateAsync()
      .then((s) => window.location.replace(s.url))
      .catch((e: Error) => setNote(e.message));
    // `mint` is a fresh object each render; the ref makes this run once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [arrival, ready, isLoggedIn]);

  async function open() {
    setNote(null);
    // Before any await: a window.open after the POST resolves is what popup
    // blockers refuse.
    const tab: TabHandle =
      typeof window !== 'undefined' ? (window.open('', '_blank') as unknown as TabHandle) : null;
    try {
      const s = await mint.mutateAsync();
      const sent = sendTab(tab, s.url, (u) => window.open(u, '_blank') as unknown as TabHandle);
      if (!sent) setNote('Your browser blocked the tab — allow pop-ups for this site and try again.');
    } catch (e) {
      tab?.close?.();
      setNote((e as Error).message);
    }
  }

  return (
    <span className="open-grafana">
      <Button
        size="sm"
        onClick={open}
        disabled={mint.isPending}
        title="Open Grafana as your noomesh account (admin→Admin, operator→Editor, user→Viewer); the session lasts 5 minutes"
      >
        {mint.isPending ? 'Opening…' : 'Open Grafana'}
      </Button>
      {note && <span className="state err open-grafana-note">{note}</span>}
    </span>
  );
}

const DOOR_LABEL = { running: 'up', down: 'down', missing: 'missing' } as const;

/**
 * The backend's mTLS door (its stunnel sidecar), shown as part of the backend
 * rather than as a second container. Warns when the door is missing or down
 * while the backend runs, and flags a door left behind with no backend.
 */
function DoorBadge({ row }: { row: ContainerRow }) {
  if (row.orphanDoor) {
    return (
      <span className="door-badge warn" title={row.doorWarning ?? undefined}>
        orphan mTLS door
      </span>
    );
  }
  if (!row.doorState) return null;
  const d = row.door;
  const title =
    row.doorWarning ??
    (d ? `${d.name}: ${d.status} · cpu ${d.cpu.toFixed(1)}% · mem ${gb(d.memUsed)} GB` : undefined);
  return (
    <span className={cn('door-badge', row.doorWarning ? 'warn' : row.doorState)} title={title}>
      mTLS door {DOOR_LABEL[row.doorState]}
    </span>
  );
}

export function ObservabilityPanel() {
  const obs = useObservability();

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Observe</h2>
        <div className="panel-head-right">
          <span className="meta">{obs.isFetching ? 'refreshing…' : 'live'}</span>
          <OpenGrafana />
        </div>
      </div>

      {obs.isLoading && <div className="state">Loading telemetry…</div>}
      {obs.isError && <div className="state err">{(obs.error as Error)?.message}</div>}

      {obs.data && (
        <>
          <div className="health-row">
            {obs.data.deps.map((d) => (
              <span
                key={d.name}
                className={cn('health-pill', d.status)}
                title={d.status === 'unknown' ? 'No health data reported' : undefined}
              >
                {d.name}
              </span>
            ))}
          </div>

          {/* Separate row from the dependency pills on purpose. A disabled
              add-on is a configuration choice, not a fault — mixing it in with
              Postgres/NATS would read as "something is wrong" to anyone
              scanning for red. */}
          {!!obs.data.addons.length && (
            <div className="addon-row">
              {obs.data.addons.map((a) => (
                <span key={a.id} className={cn('addon-pill', a.state)} title={ADDON_HINT[a.state](a.label)}>
                  {a.label}
                  <span className="addon-state">{ADDON_BADGE[a.state]}</span>
                </span>
              ))}
            </div>
          )}

          <h3 className="subhead">GPU telemetry</h3>
          {obs.data.gpus.length ? (
            obs.data.gpus.map((g, i) => (
              <div className="gpu-row" key={`${g.name}-${i}`}>
                <div className="gpu-id">
                  <span className="gpu-name">{g.name}</span>
                </div>
                <div className="gpu-metrics">
                  <span className="gpu-stat">{g.temp === null ? '—' : `${g.temp}°C`}</span>
                  <span className="meter gpu-util">
                    {g.util === null ? '—' : `${g.util}%`}
                    <span className="track">
                      <span
                        className={cn('fill', g.util === null ? '' : meterLevel(g.util, 'high-bad'))}
                        style={{ width: `${Math.min(100, g.util ?? 0)}%` }}
                      />
                    </span>
                  </span>
                  <span className="gpu-stat">
                    {g.vramUsed === null
                      ? '—'
                      : g.vramTotal !== null && g.vramTotal > 0
                        ? `${g.vramUsed.toFixed(1)} / ${g.vramTotal.toFixed(1)} GB`
                        : `${g.vramUsed.toFixed(1)} GB`}
                  </span>
                  <span className="gpu-stat">{g.power === null ? '—' : `${Math.round(g.power)}W`}</span>
                </div>
              </div>
            ))
          ) : (
            <div className="state">No GPU metrics.</div>
          )}

          <h3 className="subhead">Containers</h3>
          {!obs.data.containersAvailable ? (
            <div className="state">Container stats need the operator role.</div>
          ) : obs.data.containers.length ? (
            <div className="cache-list">
              {groupBackendDoors(obs.data.containers).map((c, i) => (
                <div className="obs-container" key={`${c.node}-${c.name}-${i}`}>
                  <div className="obs-c-id">
                    <span className={cn('c-dot', c.status === 'running' ? 'ok' : 'down')} />
                    <span className="c-name">{c.name}</span>
                    <span className="c-node">{c.node}</span>
                    <DoorBadge row={c} />
                  </div>
                  <div className="obs-c-metrics">
                    <span>cpu {c.cpu.toFixed(1)}%</span>
                    <span>
                      mem {gb(c.memUsed)}/{gb(c.memLimit)} GB
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="state">No containers running.</div>
          )}
        </>
      )}
    </section>
  );
}
